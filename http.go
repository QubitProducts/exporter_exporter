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
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	log "github.com/sirupsen/logrus"
)

const (
	// Msg to send in response body when verification of proxied server
	// response is failed
	VerificationErrorMsg = "Internal Server Error: " +
		"Response from proxied server failed verification. " +
		"See server logs for details"
)

type VerifyError struct {
	msg   string
	cause error
}

func (e *VerifyError) Error() string { return e.msg + ": " + e.cause.Error() }
func (e *VerifyError) Unwrap() error { return e.cause }

func (cfg moduleConfig) getReverseProxyDirectorFunc() func(*http.Request) {
	return func(r *http.Request) {
		vs := r.URL.Query()
		vs["module"] = vs["module"][1:]
		r.URL.RawQuery = vs.Encode()

		for k, v := range cfg.HTTP.Headers {
			r.Header.Add(k, v)
		}
		r.URL.Scheme = cfg.HTTP.Scheme
		r.URL.Host = net.JoinHostPort(cfg.HTTP.Address, strconv.Itoa(cfg.HTTP.Port))
		r.URL.Path = cfg.HTTP.Path
	}
}

func (cfg moduleConfig) getReverseProxyModifyResponseFunc() func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode != 200 {
			return nil
		}

		var (
			err     error
			body    bytes.Buffer
			oldBody = resp.Body
		)
		defer oldBody.Close()

		if _, err = body.ReadFrom(oldBody); err != nil {
			return &VerifyError{"Failed to read body from proxied server", err}
		}

		resp.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		var bodyReader io.ReadCloser
		if resp.Header.Get("Content-Encoding") == "gzip" {
			bodyReader, err = gzip.NewReader(bytes.NewReader(body.Bytes()))
			if err != nil {
				return &VerifyError{"Failed to decode gzipped response", err}
			}
		} else {
			bodyReader = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		}
		defer bodyReader.Close()

		dec := expfmt.NewDecoder(bodyReader, expfmt.ResponseFormat(resp.Header))
		for {
			mf := dto.MetricFamily{}
			err := dec.Decode(&mf)
			if err == io.EOF {
				break
			}
			if err != nil {
				proxyMalformedCount.WithLabelValues(cfg.name).Inc()
				return &VerifyError{"Failed to decode metrics from proxied server", err}
			}
		}

		return nil
	}
}

func (cfg moduleConfig) getReverseProxyErrorHandlerFunc() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		var verifyError *VerifyError
		if errors.As(err, &verifyError) {
			log.Errorf("Verification for module '%s' failed: %v", cfg.name, err)
			http.Error(w, VerificationErrorMsg, http.StatusInternalServerError)
			return
		}

		if errors.Is(err, context.DeadlineExceeded) {
			log.Errorf("Request time out for module '%s'", cfg.name)
			http.Error(w, http.StatusText(http.StatusGatewayTimeout), http.StatusGatewayTimeout)
			return
		}

		log.Errorf("Proxy error for module '%s': %v", cfg.name, err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
}

// BearerAuthMiddleware
type BearerAuthMiddleware struct {
	http.Handler
	Token string
}

func (b BearerAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Authorization header is missing"))
		return
	}
	ss := strings.SplitN(authHeader, " ", 2)
	if !(len(ss) == 2 && ss[0] == "Bearer") {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Authorization header not of Bearer type"))
		return
	}
	if ss[1] != b.Token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid Bearer Token"))
		return
	}
	b.Handler.ServeHTTP(w, r)
}

type IPAddressAuthMiddleware struct {
	http.Handler
	ACL []net.IPNet
}

func (m IPAddressAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Errorf("Failed to parse host form remote address '%s'", r.RemoteAddr)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to determine client IP address"))
		return
	}

	addr := net.ParseIP(host)
	if addr == nil {
		log.Errorf(
			"Failed to determine client IP address from '%s' (originally '%s')",
			host, r.RemoteAddr,
		)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to determine client IP address"))
		return
	}

	for _, network := range m.ACL {
		// client is in access list
		if network.Contains(addr) {
			m.Handler.ServeHTTP(w, r)
			return
		}
	}

	// client is not in access list
	log.Infof("Access forbidden for %q", addr)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Forbidden"))
}
