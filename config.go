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
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/golang/glog"
	"github.com/pkg/errors"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	Global struct {
	}
	Modules map[string]*moduleConfig
	XXX     map[string]interface{} `yaml:",inline"`
}

type moduleConfig struct {
	Method  string                 `yaml:"method"`
	Timeout time.Duration          `yaml:"timeout"`
	XXX     map[string]interface{} `yaml:",inline"`

	Exec execConfig `yaml:"exec"`
	HTTP httpConfig `yaml:"http"`

	name string
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
	XXX                   map[string]interface{} `yaml:",inline"`

	tlsConfig *tls.Config
	mcfg      *moduleConfig
}

type execConfig struct {
	Command string                 `yaml:"command"`
	Args    []string               `yaml:"args"`
	Env     map[string]string      `yaml:"env"`
	XXX     map[string]interface{} `yaml:",inline"`

	mcfg *moduleConfig
}

func readConfig(r io.Reader) (*config, error) {
	buf := bytes.Buffer{}
	io.Copy(&buf, r)
	cfg := config{}

	err := yaml.Unmarshal(buf.Bytes(), &cfg)

	if len(cfg.XXX) != 0 {
		glog.Fatalf("Unkown configuration fields: %v", cfg.XXX)
	}

	for s := range cfg.Modules {
		if err := checkModuleConfig(s, cfg.Modules[s]); err != nil {
			return nil, err
		}
	}

	return &cfg, err
}

func readModuleConfig(name string, r io.Reader) (*moduleConfig, error) {
	buf := bytes.Buffer{}
	io.Copy(&buf, r)
	cfg := moduleConfig{}

	err := yaml.Unmarshal(buf.Bytes(), &cfg)
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
		return fmt.Errorf("Unkown module configuration fields: %v", cfg.XXX)
	}

	switch cfg.Method {
	case "http":
		if len(cfg.HTTP.XXX) != 0 {
			glog.Fatalf("Unknown http module configuration fields: %v", cfg.HTTP.XXX)
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

		var err error
		cfg.HTTP.tlsConfig, err = cfg.HTTP.getTLSConfig()
		if err != nil {
			return errors.Wrap(err, "could not create tls config")
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
