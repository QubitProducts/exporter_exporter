// Copyright 2016 Tristan Colgate-McFarlane
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
	"flag"
	"net/http"
	"time"

	"github.com/doneland/yquotes"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr = flag.String("listen-address", ":9666", "The address to listen on for HTTP requests.")

	// These are metrics for the collector itself
	queryDuration = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "yquotes_query_duration_seconds",
			Help: "Duration of queries to the yahoo API",
		},
	)
	queryCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yquotes_queries_total",
			Help: "Count of completed queries",
		},
		[]string{"symbol"},
	)
	errorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "yquotes_failed_queries_total",
			Help: "Count of failed queries",
		},
		[]string{"symbol"},
	)
)

func init() {
	// register the collector metrics in the default
	// registry.
	prometheus.MustRegister(queryDuration)
	prometheus.MustRegister(queryCount)
	prometheus.MustRegister(errorCount)
}

func main() {
	flag.Parse()
	http.HandleFunc("/price", getPrice)
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(*addr, nil)
}

type collector []string

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	// Must send one description, or the registry panics
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c {
		if s == "" {
			// should never happen
			continue
		}

		queryCount.WithLabelValues(s).Inc()
		if glog.V(2) {
			glog.Infof("looking up %s\n", s)
		}

		start := time.Now()
		stock, err := yquotes.NewStock(s, false)
		queryDuration.Observe(float64(time.Since(start).Seconds()))

		if err != nil {
			glog.Infof("error: %v\n", err)
			errorCount.WithLabelValues(s).Inc()
			continue
		}

		symbol := stock.Symbol
		name := stock.Name
		price := stock.Price

		ls := []string{"symbol", "name"}
		lvs := []string{symbol, name}

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_last_price_dollars", "Last price paid.", ls, nil),
			prometheus.GaugeValue,
			price.Last,
			lvs...,
		)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_bid_price_dollars", "Bid price.", ls, nil),
			prometheus.GaugeValue,
			price.Bid,
			lvs...,
		)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_ask_price_dollars", "Asking price.", ls, nil),
			prometheus.GaugeValue,
			price.Ask,
			lvs...,
		)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_opening_price_dollars", "Opening price.", ls, nil),
			prometheus.GaugeValue,
			price.Open,
			lvs...,
		)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_previous_close_price_dollars", "Previous close price.", ls, nil),
			prometheus.GaugeValue,
			price.PreviousClose,
			lvs...,
		)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("yquotes_publish_timestamp", "The time this data was published.", ls, nil),
			prometheus.GaugeValue,
			float64(price.Date.UnixNano())/float64(time.Second),
			lvs...,
		)
	}
}

func getPrice(w http.ResponseWriter, r *http.Request) {
	syms, ok := r.URL.Query()["sym"]
	if !ok {
		glog.Infof("no syms given")
		return
	}

	registry := prometheus.NewRegistry()

	collector := collector(syms)
	registry.MustRegister(collector)

	// Delegate http serving to Promethues client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
