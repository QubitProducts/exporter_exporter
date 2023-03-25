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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	log "github.com/sirupsen/logrus"
)

var (
	fileStartsCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_command_starts_total",
			Help: "Counts of command starts",
		},
		[]string{"module"},
	)
	fileFailsCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "expexp_command_fails_total",
			Help: "Count of commands with non-zero exits",
		},
		[]string{"module"},
	)
)

func readFileWithDeadline(path string, t time.Time) ([]byte, time.Time, error) {
	f, err := os.Open(path)
	mtime := time.Time{}
	if err != nil {
		return nil, mtime, err
	}
	defer f.Close()
	f.SetDeadline(t)

	if info, err := f.Stat(); err == nil {
		if info.Mode().IsRegular() {
			mtime = info.ModTime()
		}
	}
	data, err := io.ReadAll(f)
	return data, mtime, err
}

var (
	mtimeName = "expexp_file_mtime_timestamp"
	mtimeHelp = "Time of modification of parsed file"
	mtimeType = dto.MetricType_GAUGE
	mtimeLabelModule = "module"
	mtimeLabelPath   = "path"
)

func (c fileConfig) GatherWithContext(ctx context.Context, r *http.Request) prometheus.GathererFunc {
	return func() ([]*dto.MetricFamily, error) {

		errc := make(chan error, 1)
		datc := make(chan []byte, 1)
		timec := make(chan time.Time, 1)
		go func() {
			deadline, ok := ctx.Deadline()
			if ! ok { deadline = time.Now().Add(time.Minute * 5) }
			dat, mtime, err := readFileWithDeadline(c.Path, deadline)
			errc <- err
			if err == nil {
			    datc <- dat
			    timec <- mtime
			}
			close(errc)
			close(datc)
			close(timec)
		}()

		err := <- errc
		if err != nil {
			log.Warnf("File module %v failed to read file %v, %+v", c.mcfg.name, c.Path, err)
			fileFailsCount.WithLabelValues(c.mcfg.name).Inc()
			if err == context.DeadlineExceeded || err == os.ErrDeadlineExceeded {
				proxyTimeoutCount.WithLabelValues(c.mcfg.name).Inc()
			}
			return nil, err
		}
		dat := <- datc
		mtime := <- timec
		var prsr expfmt.TextParser

		var mtimeBuf *int64 = nil
		if ! mtime.IsZero() {
			mtimeBuf = new(int64)
			*mtimeBuf = mtime.UnixMilli()
		}

		var result []*dto.MetricFamily
		mfs, err := prsr.TextToMetricFamilies(bytes.NewReader(dat))
		if err != nil {
			proxyMalformedCount.WithLabelValues(c.mcfg.name).Inc()
			return nil, err
		}
		for _, mf := range mfs {
			if c.UseMtime && mtimeBuf != nil {
				for _, m := range mf.GetMetric() {
					if (m.TimestampMs == nil) {
						m.TimestampMs = mtimeBuf
					}
				}
			}
			result = append(result, mf)
		}
		if !mtime.IsZero() {
			v := float64(mtime.Unix())
			g := dto.Gauge { Value: &v, }
			l := make([]*dto.LabelPair, 2)
			l[0] = &dto.LabelPair{
				Name:&mtimeLabelModule,
				Value:&c.mcfg.name,
			}
			l[1] = &dto.LabelPair{
				Name:&mtimeLabelPath,
				Value:&c.Path,
			}
			m := dto.Metric {
				Label: l,
				Gauge: &g,
			}
			mf := dto.MetricFamily{
				Name: &mtimeName,
				Help: &mtimeHelp,
				Type: &mtimeType,
			}
			mf.Metric = append(mf.Metric, &m)
			result = append(result, &mf)
		}
		return result, nil
	}
}

func (c fileConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g := c.GatherWithContext(ctx, r)
	promhttp.HandlerFor(g, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
