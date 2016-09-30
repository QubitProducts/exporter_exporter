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
	"fmt"
	"io"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type config struct {
	Global struct {
	}
	Modules map[string]moduleConfig
}

type moduleConfig struct {
	Method  string        `yaml:"method"`
	Timeout time.Duration `yaml:"timeout"`

	Exec execConfig `yaml:"exec"`
	HTTP httpConfig `yaml:"http"`

	name string
}

type httpConfig struct {
	Verify  *bool  `yaml:"verify"`  // no default
	Port    int    `yaml:"port"`    // no default
	Path    string `yaml:"path"`    // /metrics
	Scheme  string `yaml:"scheme"`  // http
	Address string `yaml:"address"` // 127.0.0.1

	mcfg *moduleConfig
}

type execConfig struct {
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`

	mcfg *moduleConfig
}

func readConfig(r io.Reader) (*config, error) {
	buf := bytes.Buffer{}
	io.Copy(&buf, r)
	cfg := config{}

	err := yaml.Unmarshal(buf.Bytes(), &cfg)

	for s := range cfg.Modules {
		if cfg.Modules[s].Method == "http" {
			hcfg := cfg.Modules[s]
			if hcfg.HTTP.Port == 0 {
				return nil, fmt.Errorf("module %v must have a non-zero port set", s)
			}
			if hcfg.HTTP.Verify == nil {
				v := true
				hcfg.HTTP.Verify = &v
			}
			if hcfg.HTTP.Scheme == "" {
				hcfg.HTTP.Scheme = "http"
			}
			if hcfg.HTTP.Path == "" {
				hcfg.HTTP.Path = "/metrics"
			}
			if hcfg.HTTP.Address == "" {
				hcfg.HTTP.Address = "localhost"
			}
			cfg.Modules[s] = hcfg
		}
		if cfg.Modules[s].Method == "exec" {
		}
	}

	return &cfg, err
}
