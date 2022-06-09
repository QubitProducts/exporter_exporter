// Copyright 2016 Qubit Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	Global    struct{}
	Modules   map[string]*moduleConfig
	Discovery *discoveryConfig
	XXX       map[string]interface{} `yaml:",inline"`

	bearerToken   string
	proxyPath     string
	telemetryPath string

	mutex sync.Mutex
}

func newConfig() *config {
	return &config{
		Modules: make(map[string]*moduleConfig),
		Discovery: &discoveryConfig{
			Exporters: make(map[string]*exporter),
		},
		XXX: make(map[string]interface{}),
	}
}

func (cfg *config) GetModules() map[string]*moduleConfig {
	mods := make(map[string]*moduleConfig)

	cfg.mutex.Lock()
	for k, v := range cfg.Modules {
		mods[k] = v
	}
	cfg.mutex.Unlock()
	return mods
}

func (cfg *config) getModule(name string) *moduleConfig {
	cfg.mutex.Lock()
	defer cfg.mutex.Unlock()
	if m, ok := cfg.Modules[name]; ok {
		return m
	}
	return nil
}

func (cfg *config) addModule(name string, m *moduleConfig) {
	cfg.mutex.Lock()
	cfg.Modules[name] = m
	cfg.mutex.Unlock()
}

type moduleConfig struct {
	Method  string                 `yaml:"method"`
	Timeout time.Duration          `yaml:"timeout"`
	XXX     map[string]interface{} `yaml:",inline"`

	Exec execConfig `yaml:"exec"`
	HTTP httpConfig `yaml:"http"`

	name string
}

type discoveryConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interval  string `yaml:"interval"`
	interval  time.Duration
	Address   string               `yaml:"target"` // default localhost
	Exporters map[string]*exporter `yaml:"exporters"`
}

type exporter struct {
	Port   int    `yaml:"port"`
	Path   string `yaml:"path"`
	Verify *bool  `yaml:"verify"`
}

type httpConfig struct {
	Verify                *bool                  `yaml:"verify"`                   // no default
	TLSInsecureSkipVerify bool                   `yaml:"tls_insecure_skip_verify"` // false
	TLSCertFile           *string                `yaml:"tls_cert_file"`            // no default
	TLSKeyFile            *string                `yaml:"tls_key_file"`             // no default
	TLSCACertFile         *string                `yaml:"tls_ca_cert_file"`         // no default
	Port                  int                    `yaml:"port"`                     // no default
	Path                  string                 `yaml:"path"`                     // /metrics
	Scheme                string                 `yaml:"scheme"`                   // http
	Address               string                 `yaml:"address"`                  // 127.0.0.1
	Headers               map[string]string      `yaml:"headers"`                  // no default
	BasicAuthUsername     string                 `yaml:"basic_auth_username"`      // no default
	BasicAuthPassword     string                 `yaml:"basic_auth_password"`      // no default
	XXX                   map[string]interface{} `yaml:",inline"`

	tlsConfig              *tls.Config
	mcfg                   *moduleConfig
	*httputil.ReverseProxy `json:"-"`
}

type execConfig struct {
	Command string                 `yaml:"command"`
	Args    []string               `yaml:"args"`
	Env     map[string]string      `yaml:"env"`
	XXX     map[string]interface{} `yaml:",inline"`

	mcfg *moduleConfig
}

func readConfig(r io.Reader) (*config, error) {
	cfg := config{}
	err := yaml.NewDecoder(r).Decode(&cfg)

	if len(cfg.XXX) != 0 {
		return nil, fmt.Errorf("Unknown configuration fields: %v", cfg.XXX)
	}

	for s := range cfg.Modules {
		if err := checkModuleConfig(s, cfg.Modules[s]); err != nil {
			return nil, fmt.Errorf("bad config for module %s, %w", s, err)
		}
	}

	return &cfg, err
}

func readModuleConfig(name string, r io.Reader) (*moduleConfig, error) {
	cfg := moduleConfig{}
	err := yaml.NewDecoder(r).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	if err = checkModuleConfig(name, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func checkModuleConfig(name string, cfg *moduleConfig) error {
	if len(cfg.XXX) != 0 {
		return fmt.Errorf("unknown module configuration fields: %v", cfg.XXX)
	}

	cfg.name = name

	switch cfg.Method {
	case "http":
		if len(cfg.HTTP.XXX) != 0 {
			return fmt.Errorf("Unknown http module configuration fields: %v", cfg.HTTP.XXX)
		}

		if cfg.HTTP.Port == 0 {
			return fmt.Errorf("module %v must have a non-zero port set", name)
		}
		if cfg.HTTP.Verify == nil {
			v := true
			cfg.HTTP.Verify = &v
		}
		if cfg.HTTP.Scheme == "" {
			cfg.HTTP.Scheme = "http"
		}
		if cfg.HTTP.Path == "" {
			cfg.HTTP.Path = "/metrics"
		}
		if cfg.HTTP.Address == "" {
			cfg.HTTP.Address = "localhost"
		}

		tlsConfig, err := cfg.HTTP.getTLSConfig()
		if err != nil {
			return fmt.Errorf("could not create tls config, %w", err)
		}

		dirFunc, err := cfg.getReverseProxyDirectorFunc()
		if err != nil {
			return err
		}

		cfg.HTTP.tlsConfig = tlsConfig
		cfg.HTTP.ReverseProxy = &httputil.ReverseProxy{
			Transport:    &http.Transport{TLSClientConfig: tlsConfig},
			Director:     dirFunc,
			ErrorHandler: cfg.getReverseProxyErrorHandlerFunc(),
		}
		if *cfg.HTTP.Verify {
			cfg.HTTP.ReverseProxy.ModifyResponse = cfg.getReverseProxyModifyResponseFunc()
		}
	case "exec":
		if len(cfg.Exec.XXX) != 0 {
			return fmt.Errorf("Unknown exec module configuration fields: %v", cfg.Exec.XXX)
		}
	default:
		return fmt.Errorf("Unknown module method: %v", cfg.Method)
	}

	return nil
}

func (c httpConfig) getTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: c.TLSInsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if c.TLSCACertFile != nil {
		caCert, err := ioutil.ReadFile(*c.TLSCACertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ca from %v, %w", *c.TLSCACertFile, err)
		}

		config.ClientCAs = x509.NewCertPool()
		config.ClientCAs.AppendCertsFromPEM(caCert)
	}
	if c.TLSCertFile != nil && c.TLSKeyFile != nil {
		cert, err := tls.LoadX509KeyPair(*c.TLSCertFile, *c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading TLS credentials, %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}
