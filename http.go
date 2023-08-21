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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	log "github.com/sirupsen/logrus"
)

const (
	// VerificationErrorMsg to send in response body when verification of proxied server
	// response is failed
	VerificationErrorMsg = "Internal Server Error: " +
		"Response from proxied server failed verification. " +
		"See server logs for details"
)

// VerifyError is an error type that supports reporting verification errors
type VerifyError struct {
	msg   string
	cause error
}

func (e *VerifyError) Error() string { return e.msg + ": " + e.cause.Error() }
func (e *VerifyError) Unwrap() error { return e.cause }

func (cfg moduleConfig) getReverseProxyDirectorFunc() (func(*http.Request), error) {
	base, err := url.Parse(cfg.HTTP.Path)
	if err != nil {
		return nil, fmt.Errorf("http configuration path should be a valid URL path with options, %w", err)
	}

	cvs := base.Query()

	return func(r *http.Request) {
		qvs := r.URL.Query()
		for k, vs := range cvs {
			for _, v := range vs {
				qvs.Add(k, v)
			}
		}
		qvs["module"] = qvs["module"][1:]

		r.URL.RawQuery = qvs.Encode()

		for k, v := range cfg.HTTP.Headers {
			r.Header.Add(k, v)
		}

		r.URL.Scheme = cfg.HTTP.Scheme
		r.URL.Host = net.JoinHostPort(cfg.HTTP.Address, strconv.Itoa(cfg.HTTP.Port))
		if _, ok := cfg.HTTP.Headers["host"]; ok {
			r.Host = cfg.HTTP.Headers["host"]
		}
		r.URL.Path = base.Path
		if cfg.HTTP.BasicAuthUsername != "" && cfg.HTTP.BasicAuthPassword != "" {
			r.SetBasicAuth(cfg.HTTP.BasicAuthUsername, cfg.HTTP.BasicAuthPassword)
		}
	}, nil
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

		resp.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

		var bodyReader io.ReadCloser
		if resp.Header.Get("Content-Encoding") == "gzip" {
			bodyReader, err = gzip.NewReader(bytes.NewReader(body.Bytes()))
			if err != nil {
				return &VerifyError{"Failed to decode gzipped response", err}
			}
		} else {
			bodyReader = io.NopCloser(bytes.NewReader(body.Bytes()))
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

// aha start
func (cfg moduleConfig) getLabelExtendReverseProxyModifyResponseFunc() func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode != 200 {
			return nil
		}

		// Since the body is extended the header Content-Length must be removed
		resp.Header.Del("Content-Length")

		var (
			err     error
			body    bytes.Buffer
			oldBody = resp.Body
		)
		defer oldBody.Close()

		if _, err = body.ReadFrom(oldBody); err != nil {
			return &VerifyError{"Failed to read body from proxied server", err}
		}

		resp.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

		var bodyReader io.ReadCloser
		if resp.Header.Get("Content-Encoding") == "gzip" {
			bodyReader, err = gzip.NewReader(bytes.NewReader(body.Bytes()))
			if err != nil {
				return &VerifyError{"Failed to decode gzipped response", err}
			}
		} else {
			bodyReader = io.NopCloser(bytes.NewReader(body.Bytes()))
		}
		defer bodyReader.Close()

		dec := expfmt.NewDecoder(bodyReader, expfmt.ResponseFormat(resp.Header))

		out := &bytes.Buffer{}

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

			// Validate that the target name exists in the configuration file
			// url include target=device1.foo.com
			labelKeyNames := getTargetMatch(resp.Request, cfg)
			if labelKeyNames == nil {
				continue
			}

			err = cfg.manageExtendedLabels(mf, labelKeyNames, out)
			if err != nil {
				return &VerifyError{"Failed to extend labels on metrics from proxied server", err}

			}

		}

		// Prometheus always request with "Accept-Encoding: gzip"
		if resp.Request.Header.Get("Accept-Encoding") == "gzip" {
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			defer gz.Close()
			_, err = gz.Write(out.Bytes())
			gz.Flush()
			resp.Body = io.NopCloser(&b)
		} else {
			resp.Body = io.NopCloser(out)
		}
		return nil
	}
}

func (cfg moduleConfig) manageExtendedLabels(mf dto.MetricFamily, labelKeyNames *ExtendedLabelTarget, out *bytes.Buffer) error {

	var labelIndexMap map[string]*MetricLabelMeta

	for index, metric := range mf.Metric {
		if index == 0 && metric.Label == nil {
			//continue
			break
		}

		// Check the first metric of all the same type
		if index == 0 {
			// return the label map indicate if the label_key_names exist in the metrics
			labelIndexMap = resolveLabels(metric, labelKeyNames)
		}

		// For every label_key_name
		for _, extendedLabel := range labelKeyNames.Labels {

			// Evaluate the first row of the mf.Metric to check if label exist and index in metric.Label
			if labelIndexMap[extendedLabel.MatchLabelKey].LabelExist {
				var matchLabelPair *dto.LabelPair
				// if the label exists in the metric
				matchLabelPair = metric.Label[labelIndexMap[extendedLabel.MatchLabelKey].LabelIndex]
				if matchLabelPair != nil {
					for _, matchLabel := range extendedLabel.MatchLabels {
						defaultAddLabels := matchLabel.DefaultLabelPairs

						// check if metric name matcher is true
						if !matchMetricsName(mf.GetName(), matchLabel.MetricMatch) {
							continue
						}

						for matchKey, addLabels := range matchLabel.MatchLabelValues {

							// check if the metric label value match match_label_key_values
							if !(matchLabelPair.GetValue() == matchKey || "*" == matchKey) {
								continue
							}

							if addLabels != nil {
								addExtendedLabels(addLabels.LabelPair, metric)
							}

							if defaultAddLabels != nil {
								addExtendedLabels(defaultAddLabels, metric)
							}
						}
					}
				}
			}
		}
	}

	_, err := expfmt.MetricFamilyToText(out, &mf)
	if err != nil {
		if err != nil {
			proxyMalformedCount.WithLabelValues(cfg.name).Inc()
			return &VerifyError{"Failed to inject labels from proxied server", err}
		}
	}
	return nil
}

func addExtendedLabels(defaultAddLabels map[string]string, metric *dto.Metric) {
	for addLabelKey, addLabelValue := range defaultAddLabels {
		k := addLabelKey
		v := addLabelValue
		var label = dto.LabelPair{
			Name:  &k,
			Value: &v,
		}
		metric.Label = append(metric.Label, &label)
	}
}

func matchMetricsName(name string, matchMetricsName *string) bool {
	if matchMetricsName == nil {
		return true
	}
	match, err := regexp.MatchString(*matchMetricsName, name)
	if err != nil {
		// log
		return false
	}
	return match
}

func getTargetMatch(request *http.Request, cfg moduleConfig) *ExtendedLabelTarget {
	target := request.URL.Query().Get(*cfg.HTTP.ExtendLabelsTargetURLIdentity)
	kalle := cfg.HTTP.LabelExtendConfig.Targets[target]
	return &kalle
}

func resolveLabels(metric *dto.Metric, ingestor *ExtendedLabelTarget) map[string]*MetricLabelMeta {
	metricLabelMeta := make(map[string]*MetricLabelMeta)
	for _, key := range ingestor.getMatchKeys() {
		metricLabel := MetricLabelMeta{
			LabelIndex: 0,
			LabelExist: false,
		}
		metricLabelMeta[key] = &metricLabel
		for index, label := range metric.Label {
			if key == label.GetName() {
				metricLabel.LabelExist = true
				metricLabel.LabelIndex = index
				break
			}
		}
	}
	return metricLabelMeta
}

type MetricLabelMeta struct {
	LabelIndex int
	LabelExist bool
}

func (cfg moduleConfig) getReverseProxyErrorHandlerFunc() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
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

// BearerAuthMiddleware checks an Authorization: Berarer header for a known
// token
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

// IPAddressAuthMiddleware matches all incoming requests to a known
// set of remote net.IPNet networks
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
