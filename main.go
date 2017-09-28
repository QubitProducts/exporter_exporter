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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	printVersion = flag.Bool("version", false, "Print the version and exit")

	cfgFile  = flag.String("config.file", "expexp.yaml", "The path to the configuration file.")
	cfgDirs  StringSliceFlag
	skipDirs = flag.Bool("config.skip-dirs", false, "Skip non existent -config.dirs entries instead of terminating.")

	addr = flag.String("web.listen-address", ":9999", "The address to listen on for HTTP requests.")

	bearerToken     = flag.String("web.bearer.token", "", "Bearer authentication token.")
	bearerTokenFile = flag.String("web.bearer.token-file", "", "File containing the Bearer authentication token.")

	certPath = flag.String("web.tls.cert", "cert.pem", "Path to cert")
	keyPath  = flag.String("web.tls.key", "key.pem", "Path to key")
	caPath   = flag.String("web.tls.ca", "ca.pem", "Path to CA to auth clients against")
	verify   = flag.Bool("web.tls.verify", false, "Disable client verification")
	tlsAddr  = flag.String("web.tls.listen-address", "", "The address to listen on for HTTPS requests.")

	tPath = flag.String("web.telemetry-path", "/metrics", "The address to listen on for HTTP requests.")
	mPath = flag.String("web.proxy-path", "/proxy", "The address to listen on for HTTP requests.")

	proxyDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "expexp_proxy_duration_seconds",
			Help: "Duration of queries to the yahoo API",
		},
		[]string{"module"},
	)
	proxyErrorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_proxy_errors_total",
			Help: "Counts of errors",
		},
		[]string{"module"},
	)
	proxyTimeoutCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_proxy_timeout_errors_total",
			Help: "Counts of the number of times a proxy timeout occurred",
		},
		[]string{"module"},
	)

	proxyMalformedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_malformed_content_errors_total",
			Help: "Counts of unparsable scrape content errors",
		},
		[]string{"module"},
	)
)

func init() {
	// register the collector metrics in the default
	// registry.
	prometheus.MustRegister(proxyDuration)
	prometheus.MustRegister(proxyTimeoutCount)
	prometheus.MustRegister(proxyErrorCount)
	prometheus.MustRegister(proxyMalformedCount)
	prometheus.MustRegister(cmdStartsCount)
	prometheus.MustRegister(cmdFailsCount)
	flag.Var(&cfgDirs, "config.dirs", "The path to directories of configuration files, can be specified multiple times.")
}

func main() {
	flag.Parse()
	if *printVersion {
		fmt.Fprintf(os.Stderr, "Version: %s\n", versionStr())
		os.Exit(0)
	}
	cfg := &config{
		Modules: make(map[string]*moduleConfig),
		XXX:     make(map[string]interface{}),
	}
	if *cfgFile != "" {
		r, err := os.Open(*cfgFile)
		if err != nil {
			glog.Fatalf("%+v", err)
		}
		cfg, err = readConfig(r)
		if err != nil {
			glog.Fatalf("%+v", err)
		}
		_ = r.Close()
		for mn, _ := range cfg.Modules {
			glog.Infof("read module config '%s' from: %s", mn, *cfgFile)
		}
	}

cfgDirs:
	for _, cfgDir := range cfgDirs {
		mfs, err := ioutil.ReadDir(cfgDir)
		if err != nil {
			if *skipDirs && os.IsNotExist(err) {
				glog.Warningf("skipping non existent config.dirs entry '%s'", cfgDir)
				continue cfgDirs
			}
			glog.Fatalf("failed reading directory: %s, %v", cfgDir, err)
		}

		yamlSuffixes := map[string]bool{
			".yml":  true,
			".yaml": true,
		}
		for _, mf := range mfs {
			fullpath := filepath.Join(cfgDir, mf.Name())
			if mf.IsDir() || !yamlSuffixes[filepath.Ext(mf.Name())] {
				glog.Warningf("skipping non-yaml file %v", fullpath)
				continue
			}
			mn := strings.TrimSuffix(mf.Name(), filepath.Ext(mf.Name()))
			if _, ok := cfg.Modules[mn]; ok {
				glog.Fatalf("module %s is already defined", mn)
			}
			r, err := os.Open(fullpath)
			if err != nil {
				glog.Fatalf("failed to open config file: %s: %v", fullpath, err)
			}
			mcfg, err := readModuleConfig(mn, r)
			_ = r.Close()
			if err != nil {
				glog.Fatalf("failed reading configs %s, %s", fullpath, err)
			}
			glog.Infof("read module config '%s' from: %s", mn, fullpath)
			cfg.Modules[mn] = mcfg
		}
	}
	if len(cfg.Modules) == 0 {
		glog.Errorln("no modules loaded from any config file")
	}

	var bToken string
	if *bearerToken != "" {
		bToken = *bearerToken
	}
	if *bearerTokenFile != "" {
		if bToken != "" {
			glog.Fatalln("web.bearer.token and web.bearer.token-file are mutually exclusive options")
		}
		f, err := os.Open(*bearerTokenFile)
		if err != nil {
			glog.Fatalf("error opening bearer.token-file '%s': %v", *bearerTokenFile, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				glog.Fatalf("error reading first line ot web.bearer.token-file '%s': %v", *bearerTokenFile, err)
			}
			glog.Fatalf("error reading token from first line of web.bearer.token-file '%s'", *bearerTokenFile)
		}
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			glog.Fatalf("first line of bearer.token-file must contain the token '%s'", *bearerTokenFile)
		}
		_ = f.Close()
		bToken = t
	}

	http.HandleFunc("/proxy", cfg.doProxy)
	http.Handle("/metrics", promhttp.Handler())

	var handler http.Handler
	if bToken == "" {
		handler = http.DefaultServeMux
	} else {
		handler = &BearerAuthMiddleware{http.DefaultServeMux, bToken}
	}

	eg, ctx := errgroup.WithContext(context.Background())

	if *addr == "" && *tlsAddr == "" {
		glog.Info("No web addresses to listen on, nothing to do!")
		os.Exit(0)
	}

	if *addr != "" {
		eg.Go(func() error {
			return http.ListenAndServe(*addr, handler)
		})
	}

	if *tlsAddr != "" {
		eg.Go(func() error {
			cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
			if err != nil {
				glog.Fatalf("Could not parse key/cert, " + err.Error())
			}

			cabs, err := ioutil.ReadFile(*caPath)
			if err != nil {
				glog.Fatalf("Could not open ca file,, " + err.Error())
			}
			pool := x509.NewCertPool()
			ok := pool.AppendCertsFromPEM(cabs)
			if !ok {
				glog.Fatalf("Failed loading ca certs")
			}

			tlsConfig := tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			}
			tlsConfig.BuildNameToCertificate()

			if *verify {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				tlsConfig.ClientCAs = pool
			}

			srvr := http.Server{
				Addr:      *tlsAddr,
				TLSConfig: &tlsConfig,
				Handler:   handler,
			}
			return srvr.ListenAndServeTLS(*certPath, *keyPath)
		})
	}

	<-ctx.Done()
	log.Fatal(ctx.Err())
}

func (cfg *config) doProxy(w http.ResponseWriter, r *http.Request) {
	mod, ok := r.URL.Query()["module"]
	if !ok {
		if glog.V(1) {
			glog.Infof("no module given")
		}
		http.Error(w, fmt.Sprintf("require parameter module is missing%v\n", mod), http.StatusBadRequest)
		return
	}

	if glog.V(3) {
		glog.Infof("running module %v\n", mod)
	}

	var h http.Handler
	if m, ok := cfg.Modules[mod[0]]; !ok {
		proxyErrorCount.WithLabelValues("unknown").Inc()
		if glog.V(1) {
			glog.Infof("unknown module requested  %v\n", mod)
		}
		http.Error(w, fmt.Sprintf("unknown module %v\n", mod), http.StatusNotFound)
		return
	} else {
		m.name = mod[0]
		h = m
	}

	h.ServeHTTP(w, r)
}

func (m moduleConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := time.Now()
	defer func() {
		proxyDuration.WithLabelValues(m.name).Observe(float64(time.Since(st)) / float64(time.Second))
	}()

	nr := r
	cancel := func() {}
	if m.Timeout != 0 {
		if glog.V(3) {
			glog.Infof("setting module %v timeout to %v", m.name, m.Timeout)
		}

		var ctx context.Context
		ctx, cancel = context.WithTimeout(r.Context(), m.Timeout)
		nr = r.WithContext(ctx)
	}
	defer cancel()

	switch m.Method {
	case "exec":
		m.Exec.mcfg = &m
		m.Exec.ServeHTTP(w, nr)
	case "http":
		m.HTTP.mcfg = &m
		m.HTTP.ServeHTTP(w, nr)
	default:
		if glog.V(1) {
			glog.Errorf("unknown module method  %v\n", m.Method)
		}
		proxyErrorCount.WithLabelValues(m.name).Inc()
		http.Error(w, fmt.Sprintf("unknown module method %v\n", m.Method), http.StatusNotFound)
		return
	}
}

// StringSliceFlags collects multiple uses of a named flag into a slice.
type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	// Just some representation output, not actually used to parse the input,
	// the flag is instead supposed to be specified multiple times.
	return strings.Join(*s, ", ")
}

func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
