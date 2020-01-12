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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

var (
	printVersion = flag.Bool("version", false, "Print the version and exit")

	cfgFile  = flag.String("config.file", "expexp.yaml", "The path to the configuration file.")
	cfgDirs  StringSliceFlag
	skipDirs = flag.Bool("config.skip-dirs", false, "Skip non existent -config.dirs entries instead of terminating.")

	addr = flag.String("web.listen-address", ":9999", "The address to listen on for HTTP requests.")

	bearerToken     = flag.String("web.bearer.token", "", "Bearer authentication token.")
	bearerTokenFile = flag.String("web.bearer.token-file", "", "File containing the Bearer authentication token.")

	acl IPNetSliceFlag

	certPath = flag.String("web.tls.cert", "cert.pem", "Path to cert")
	keyPath  = flag.String("web.tls.key", "key.pem", "Path to key")
	caPath   = flag.String("web.tls.ca", "ca.pem", "Path to CA to auth clients against")
	verify   = flag.Bool("web.tls.verify", false, "Enable client verification")
	tlsAddr  = flag.String("web.tls.listen-address", "", "The address to listen on for HTTPS requests.")

	tPath = flag.String("web.telemetry-path", "/metrics", "The address to listen on for HTTP requests.")
	pPath = flag.String("web.proxy-path", "/proxy", "The address to listen on for HTTP requests.")

	proxyDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "expexp_proxy_duration_seconds",
			Help: "Duration of proxying requests to configured exporters",
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
	flag.Var(&acl, "allow.net", "Allow connection from this network specified in CIDR notation. Can be specified multiple times.")
}

func setup() (*config, error) {
	cfg := &config{
		Modules: make(map[string]*moduleConfig),
		XXX:     make(map[string]interface{}),
	}
	if *cfgFile != "" {
		r, err := os.Open(*cfgFile)
		if err != nil {
			return nil, err
		}
		defer r.Close()

		cfg, err = readConfig(r)
		if err != nil {
			return nil, err
		}
		for mn, _ := range cfg.Modules {
			log.Debugf("read module config '%s' from: %s", mn, *cfgFile)
		}
	}

cfgDirs:
	for _, cfgDir := range cfgDirs {
		mfs, err := ioutil.ReadDir(cfgDir)
		if err != nil {
			if *skipDirs && os.IsNotExist(err) {
				log.Warnf("skipping non existent config.dirs entry '%s'", cfgDir)
				continue cfgDirs
			}
			return nil, fmt.Errorf("failed reading directory: %s, %v", cfgDir, err)
		}

		yamlSuffixes := map[string]bool{
			".yml":  true,
			".yaml": true,
		}
		for _, mf := range mfs {
			fullpath := filepath.Join(cfgDir, mf.Name())
			if mf.IsDir() || !yamlSuffixes[filepath.Ext(mf.Name())] {
				log.Warnf("skipping non-yaml file %v", fullpath)
				continue
			}

			mn := strings.TrimSuffix(mf.Name(), filepath.Ext(mf.Name()))
			if _, ok := cfg.Modules[mn]; ok {
				return nil, fmt.Errorf("module %s is already defined", mn)
			}
			r, err := os.Open(fullpath)
			if err != nil {
				return nil, fmt.Errorf("failed to open config file %s, %w", fullpath, err)
			}
			defer r.Close()

			mcfg, err := readModuleConfig(mn, r)
			if err != nil {
				return nil, fmt.Errorf("failed reading configs %s, %w", fullpath, err)
			}

			log.Debugf("read module config '%s' from: %s", mn, fullpath)
			cfg.Modules[mn] = mcfg
		}
	}
	if len(cfg.Modules) == 0 {
		log.Errorln("no modules loaded from any config file")
	}

	if *bearerToken != "" {
		cfg.bearerToken = *bearerToken
	}

	if *bearerTokenFile != "" {
		if *bearerToken != "" {
			return nil, errors.New(("web.bearer.token and web.bearer.token-file are mutually exclusive options"))
		}
		bs, err := ioutil.ReadFile(*bearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading bearer file %s, %w", *bearerTokenFile, err)
		}

		t := strings.TrimSpace(string(bs))
		if len(t) == 0 {
			return nil, errors.New("token file should not be empty")
		}
		cfg.bearerToken = t
	}

	cfg.proxyPath = path.Clean("/" + *pPath)
	cfg.telemetryPath = path.Clean("/" + *tPath)
	if cfg.proxyPath == cfg.telemetryPath {
		return nil, fmt.Errorf("flags -web.proxy-path and -web.telemetry-path can not be set to the same value")
	}
	return cfg, nil
}

func setupTLS() (*tls.Config, error) {
	var tlsConfig *tls.Config
	if *tlsAddr == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return nil, fmt.Errorf("Could not parse key/cert, %w", err)
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()

	if *verify {
		pool := x509.NewCertPool()
		cabs, err := ioutil.ReadFile(*caPath)
		if err != nil {
			return nil, fmt.Errorf("Could not open ca file, %w", err)
		}
		ok := pool.AppendCertsFromPEM(cabs)
		if !ok {
			return nil, errors.New("Failed loading ca certs")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = pool
	}

	return tlsConfig, nil
}

func runListener(ctx context.Context, name string, lsnr net.Listener, handler http.Handler) error {
	srvr := http.Server{
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		srvr.Shutdown(context.Background())
	}()

	if err := srvr.Serve(lsnr); err != nil {
		return fmt.Errorf("listener %s stopped, %w", name, err)
	}
	return nil
}

func main() {
	var err error
	defer func() {
		if err != nil {
			log.Errorln(err.Error())
			os.Exit(1)
		}
	}()

	flag.Parse()

	if *printVersion {
		fmt.Fprintf(os.Stderr, "Version: %s\n", versionStr())
		return
	}

	cfg, err := setup()
	if err != nil {
		return
	}
	tlsConfig, err := setupTLS()
	if err != nil {
		return
	}

	if *addr == "" && *tlsAddr == "" {
		log.Info("No web addresses to listen on, nothing to do!")
		os.Exit(0)
	}

	var lsnr net.Listener
	if *addr != "" {
		lsnr, err = net.Listen("tcp", *addr)
		if err != nil {
			return
		}
	}

	var tlsLsnr net.Listener
	if *tlsAddr != "" {
		tlsLsnr, err = net.Listen("tcp", *tlsAddr)
		if err != nil {
			return
		}

		tlsLsnr = tls.NewListener(tlsLsnr, tlsConfig)
	}

	http.HandleFunc(cfg.proxyPath, cfg.doProxy)
	http.HandleFunc("/", cfg.listModules)
	http.Handle(cfg.telemetryPath, promhttp.Handler())

	handler := http.Handler(http.DefaultServeMux)

	if cfg.bearerToken != "" {
		handler = &BearerAuthMiddleware{handler, cfg.bearerToken}
	}

	if len(acl) > 0 {
		log.Infof("Allowing connections only from %v", acl)
		handler = &IPAddressAuthMiddleware{handler, acl}
	}

	eg, ctx := errgroup.WithContext(context.Background())

	if lsnr != nil {
		eg.Go(func() error {
			return runListener(ctx, "http", lsnr, handler)
		})
	}

	if tlsLsnr != nil {
		eg.Go(func() error {
			return runListener(ctx, "https", tlsLsnr, handler)
		})
	}

	err = eg.Wait()
}

func (cfg *config) doProxy(w http.ResponseWriter, r *http.Request) {
	mod, ok := r.URL.Query()["module"]
	if !ok {
		log.Errorf("no module given")
		http.Error(w, fmt.Sprintf("require parameter module is missing%v\n", mod), http.StatusBadRequest)
		return
	}

	log.Debugf("running module %v\n", mod)

	var h http.Handler
	if m, ok := cfg.Modules[mod[0]]; !ok {
		proxyErrorCount.WithLabelValues("unknown").Inc()
		log.Warnf("unknown module requested  %v\n", mod)
		http.Error(w, fmt.Sprintf("unknown module %v\n", mod), http.StatusNotFound)
		return
	} else {
		h = m
	}

	h.ServeHTTP(w, r)
}

func (cfg *config) listModules(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Accept") {
	case "application/json":
		log.Debugf("Listing modules in json")
		moduleJson, err := json.Marshal(cfg.Modules)
		if err != nil {
			log.Error(err)
			http.Error(w, "Failed to produce JSON", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(moduleJson)
	default:
		log.Debugf("Listing modules in html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl := template.Must(template.New("modules").Parse(`
			<h2>Exporters:</h2>
				<ul>
					{{range $name, $cfg := .Modules}}
						<li><a href="/proxy?module={{$name}}">{{$name}}</a></li>
					{{end}}
				</ul>`))
		err := tmpl.Execute(w, cfg)
		if err != nil {
			log.Error(err)
			http.Error(w, "Can't execute the template", http.StatusInternalServerError)
		}
	}
	return
}

func (m moduleConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := time.Now()
	defer func() {
		proxyDuration.WithLabelValues(m.name).Observe(float64(time.Since(st)) / float64(time.Second))
	}()

	nr := r
	cancel := func() {}
	if m.Timeout != 0 {
		log.Debugf("setting module %v timeout to %v", m.name, m.Timeout)

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
		log.Errorf("unknown module method  %v\n", m.Method)
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

// IPNetSliceFlag parses IP network in CIDR notation into net.IPNet. Can be set
// multiple times
type IPNetSliceFlag []net.IPNet

func (nets IPNetSliceFlag) String() string {
	netsStr := make([]string, len(nets))
	for i := range nets {
		netsStr[i] = fmt.Sprint(nets[i].String())
	}
	return strings.Join(netsStr, ", ")
}

func (nets *IPNetSliceFlag) Set(value string) error {
	if _, net, err := net.ParseCIDR(value); err != nil {
		return err
	} else {
		*nets = append(*nets, *net)
	}
	return nil
}
