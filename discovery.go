package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec only cockroach at the moment
	},
}

func alive(parentCtx context.Context, host string, portI int, path string) bool {
	port := strconv.Itoa(portI)
	if path != "" {
		u := fmt.Sprintf(path, net.JoinHostPort(host, port))

		ctx, cancel := context.WithTimeout(parentCtx, time.Second*3)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			logrus.Errorf("error creating request: %s", err)
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		r := bufio.NewReader(resp.Body)
		for i := 0; i < 10; i++ {
			line, _, err := r.ReadLine()
			if err != nil {
				return false
			}
			if bytes.Contains(line, []byte("# TYPE")) {
				return true
			}
		}
		return false
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 200*time.Millisecond)
	if err != nil {
		return false
	}

	if conn != nil {
		conn.Close()
		return true
	}
	return false
}

func startDiscovery(ctx context.Context, cfg *config) {
	if cfg.Modules == nil { // make sure we have modules config if we are running only in discovery mode
		cfg.Modules = make(map[string]*moduleConfig)
	}
	ticker := time.NewTicker(cfg.Discovery.interval)
	runDiscovery(ctx, cfg)
	for {
		select {
		case <-ticker.C:
			runDiscovery(ctx, cfg)
		case <-ctx.Done():
			return
		}
	}
}

func runDiscovery(ctx context.Context, cfg *config) {
	ip := cfg.Discovery.Address
	for name, exp := range cfg.Discovery.Exporters {
		if m := cfg.getModule(name); m != nil {
			continue
		}
		if alive(ctx, ip, exp.Port, exp.Path) {
			verify := true
			if exp.Verify != nil && *exp.Verify == false {
				verify = false
			}
			mc := &moduleConfig{
				Method: "http",
				HTTP: httpConfig{
					Port:    exp.Port,
					Verify:  &verify,
					Address: cfg.Discovery.Address,
				},
			}
			if exp.Path != "" {
				u, err := url.Parse(fmt.Sprintf(exp.Path, net.JoinHostPort(ip, strconv.Itoa(exp.Port))))
				if err != nil {
					logrus.Error(err)
					continue
				}
				mc.HTTP.Scheme = u.Scheme
				mc.HTTP.Path = u.Path
			}

			err := checkModuleConfig(name, mc)
			if err != nil {
				logrus.Error(err)
			}
			cfg.addModule(name, mc)
			continue
		}
		logrus.Debugf("%s:%d was not open", ip, exp.Port)
	}
}
