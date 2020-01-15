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
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	log "github.com/sirupsen/logrus"
)

var (
	cmdStartsCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_command_starts_total",
			Help: "Counts of command starts",
		},
		[]string{"module"},
	)
	cmdFailsCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_command_fails_total",
			Help: "Count of commands with non-zero exits",
		},
		[]string{"module"},
	)
)

func (c execConfig) GatherWithContext(ctx context.Context, r *http.Request) prometheus.GathererFunc {
	return func() ([]*dto.MetricFamily, error) {
		var out bytes.Buffer

		cmd := exec.CommandContext(ctx, c.Command)
		cmd.Args = append(cmd.Args, c.Args...)
		uargs, ok := r.URL.Query()["args"]
		if ok {
			cmd.Args = append(cmd.Args, uargs...)
		}

		for k, v := range c.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}

		cmd.Stdout = &out
		cmd.Stderr = os.Stderr

		errc := make(chan error, 1)
		go func() {
			cmdStartsCount.WithLabelValues(c.mcfg.name).Inc()
			errc <- cmd.Run()
			close(errc)
		}()

		var err error
		select {
		case err = <-errc:
		case <-ctx.Done():
			err = ctx.Err()
		}

		if err != nil {
			log.Warnf("Command module %v failed %+v", c.mcfg.name, err)
			cmdFailsCount.WithLabelValues(c.mcfg.name).Inc()
			if err == context.DeadlineExceeded {
				proxyTimeoutCount.WithLabelValues(c.mcfg.name).Inc()
			}
			return nil, err
		}
		var prsr expfmt.TextParser

		var result []*dto.MetricFamily
		mfs, err := prsr.TextToMetricFamilies(&out)
		if err != nil {
			proxyMalformedCount.WithLabelValues(c.mcfg.name).Inc()
			return nil, err
		}
		for _, mf := range mfs {
			result = append(result, mf)
		}
		return result, nil
	}
}

func (c execConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g := c.GatherWithContext(ctx, r)
	promhttp.HandlerFor(g, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
