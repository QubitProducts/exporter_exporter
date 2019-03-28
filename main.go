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
	"html/template"
	"io/ioutil"
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

	certPath = flag.String("web.tls.cert", "cert.pem", "Path to cert")
	keyPath  = flag.String("web.tls.key", "key.pem", "Path to key")
	caPath   = flag.String("web.tls.ca", "ca.pem", "Path to CA to auth clients against")
	verify   = flag.Bool("web.tls.verify", false, "Disable client verification")
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
	//log.AddFlags(flag.CommandLine)
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
			log.Fatalf("%+v", err)
		}
		cfg, err = readConfig(r)
		if err != nil {
			log.Fatalf("%+v", err)
		}
		_ = r.Close()
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
			log.Fatalf("failed reading directory: %s, %v", cfgDir, err)
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
				log.Fatalf("module %s is already defined", mn)
			}
			r, err := os.Open(fullpath)
			if err != nil {
				log.Fatalf("failed to open config file: %s: %v", fullpath, err)
			}
			mcfg, err := readModuleConfig(mn, r)
			_ = r.Close()
			if err != nil {
				log.Fatalf("failed reading configs %s, %s", fullpath, err)
			}
			log.Debugf("read module config '%s' from: %s", mn, fullpath)
			cfg.Modules[mn] = mcfg
		}
	}
	if len(cfg.Modules) == 0 {
		log.Errorln("no modules loaded from any config file")
	}

	var bToken string
	if *bearerToken != "" {
		bToken = *bearerToken
	}
	if *bearerTokenFile != "" {
		if bToken != "" {
			log.Fatalln("web.bearer.token and web.bearer.token-file are mutually exclusive options")
		}
		f, err := os.Open(*bearerTokenFile)
		if err != nil {
			log.Fatalf("error opening bearer.token-file '%s': %v", *bearerTokenFile, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				log.Fatalf("error reading first line ot web.bearer.token-file '%s': %v", *bearerTokenFile, err)
			}
			log.Fatalf("error reading token from first line of web.bearer.token-file '%s'", *bearerTokenFile)
		}
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			log.Fatalf("first line of bearer.token-file must contain the token '%s'", *bearerTokenFile)
		}
		_ = f.Close()
		bToken = t
	}

	proxyPath := path.Clean("/" + *pPath)
	telePath := path.Clean("/" + *tPath)
	if proxyPath == telePath {
		log.Fatalf("flags -web.proxy-path and -web.telemetry-path can not be set to the same value: %s", proxyPath)
	}

	http.HandleFunc(proxyPath, cfg.doProxy)
	http.HandleFunc("/", cfg.listModules)
	http.Handle(telePath, promhttp.Handler())

	var handler http.Handler
	if bToken == "" {
		handler = http.DefaultServeMux
	} else {
		handler = &BearerAuthMiddleware{http.DefaultServeMux, bToken}
	}

	eg, ctx := errgroup.WithContext(context.Background())

	if *addr == "" && *tlsAddr == "" {
		log.Info("No web addresses to listen on, nothing to do!")
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
				log.Fatalf("Could not parse key/cert, " + err.Error())
			}

			tlsConfig := tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			tlsConfig.BuildNameToCertificate()

			if *verify {
				pool := x509.NewCertPool()
				cabs, err := ioutil.ReadFile(*caPath)
				if err != nil {
					log.Fatalf("Could not open ca file,, " + err.Error())
				}
				ok := pool.AppendCertsFromPEM(cabs)
				if !ok {
					log.Fatalf("Failed loading ca certs")
				}

				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				tlsConfig.ClientCAs = pool
			}

			srvr := http.Server{
				Addr:      *tlsAddr,
				TLSConfig: &tlsConfig,
				Handler:   handler,
			}

			err = srvr.ListenAndServeTLS(*certPath, *keyPath)
			if err != nil {
				log.Fatalf("Failed starting TLS server, %v", err)
			}
			return err
		})
	}

	<-ctx.Done()
	log.Fatal(ctx.Err())
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
		m.name = mod[0]
		h = m
	}

	h.ServeHTTP(w, r)
}

func (cfg *config) listModules(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Listing modules")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("modules").Parse(`
		<h2>Exporters:</h2>
			<ul>
				{{range $name, $cfg := .Modules}}
					<li><a href="/proxy?module={{$name}}">{{$name}}</a></li>
				{{end}}
			</ul>`)
	if err != nil {
		log.Error(err)
	}
	tmpl.Execute(w, cfg)
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
