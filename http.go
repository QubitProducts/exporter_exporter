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
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"golang.org/x/net/context/ctxhttp"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func (c httpConfig) GatherWithContext(ctx context.Context, r *http.Request) prometheus.GathererFunc {
	return func() ([]*dto.MetricFamily, error) {
		vs := r.URL.Query()
		vs["module"] = vs["module"][1:]

		url := &url.URL{
			Scheme:   c.Scheme,
			Host:     net.JoinHostPort(c.Address, strconv.Itoa(c.Port)),
			Path:     c.Path,
			RawQuery: vs.Encode(),
		}
		resp, err := ctxhttp.Get(ctx, c.httpClient, url.String())
		if err != nil {
			if glog.V(1) {
				glog.Errorf("http proxy for module %v failed %+v", c.mcfg.name, err)
			}
			proxyErrorCount.WithLabelValues(c.mcfg.name).Inc()
			if err == context.DeadlineExceeded {
				proxyTimeoutCount.WithLabelValues(c.mcfg.name).Inc()
			}
			return nil, err
		}
		defer resp.Body.Close()
		dec := expfmt.NewDecoder(resp.Body, expfmt.ResponseFormat(resp.Header))

		result := []*dto.MetricFamily{}
		for {
			mf := dto.MetricFamily{}
			err := dec.Decode(&mf)
			if err == io.EOF {
				break
			}
			if err != nil {
				proxyMalformedCount.WithLabelValues(c.mcfg.name).Inc()
				if glog.V(1) {
					glog.Errorf("err %+v", err)
				}
				return nil, err
			}

			result = append(result, &mf)
		}

		return result, nil
	}
}

func (c httpConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var h http.Handler

	if !(*c.Verify) {
		// proxy directly
		rt := &http.Transport{
			Dial: (&net.Dialer{
				Timeout: c.mcfg.Timeout,
			}).Dial,
			TLSHandshakeTimeout: c.mcfg.Timeout,
			TLSClientConfig:     c.tlsConfig,
		}
		h = &httputil.ReverseProxy{
			Transport: rt,
			Director: func(r *http.Request) {
				vs := r.URL.Query()
				vs["module"] = vs["module"][1:]
				r.URL.RawQuery = vs.Encode()

				r.URL.Scheme = c.Scheme
				r.URL.Host = net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
				r.URL.Path = c.Path

			},
		}
	} else {
		ctx := r.Context()
		g := c.GatherWithContext(ctx, r)
		h = promhttp.HandlerFor(g, promhttp.HandlerOpts{})
	}

	h.ServeHTTP(w, r)
}
