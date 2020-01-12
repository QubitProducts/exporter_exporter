package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func BenchmarkReverseProxyHandler(b *testing.B) {
	body := genRandomMetricsResponse(10000, 10)

	test_exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader := bytes.NewReader(body.Bytes())
		io.Copy(w, reader)
	}))
	defer test_exporter.Close()

	URL, _ := url.Parse(test_exporter.URL)
	verify := true
	port, _ := strconv.ParseInt(URL.Port(), 0, 0)
	modCfg := &moduleConfig{
		Method:  "http",
		Timeout: 5 * time.Second,
		HTTP: httpConfig{
			Verify:  &verify,
			Scheme:  URL.Scheme,
			Address: URL.Hostname(),
			Port:    int(port),
			Path:    "/",
		},
	}

	if err := checkModuleConfig("test", modCfg); err != nil {
		b.Fatalf("Failed to check module config: %v", err)
	}

	cfg := &config{
		Modules: map[string]*moduleConfig{
			"test": modCfg,
		},
	}

	req := httptest.NewRequest("GET", "/proxy?module=test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		cfg.doProxy(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("Bad response status %d", rr.Code)
		}
		if len(rr.Body.Bytes()) <= 0 {
			b.Fatal("Response body is absent")
		}
	}
}

// genRandomMetricsResponse generates http response body which contains random set of
// prometheus metrics. mf_num sets number of metric families in response which has
// metric names in format 'metric{random number}'. m_num controls number of metrics
// inside each metric family. Metrics inside metric families differ in values of
// label 'label'.
func genRandomMetricsResponse(mf_num int, m_num int) *bytes.Buffer {
	rand.Seed(time.Now().UnixNano())
	helpMsg := "help msg"
	labelName := "label"
	metricFamilies := make([]*dto.MetricFamily, mf_num)
	metricType := dto.MetricType_GAUGE
	for i, _ := range metricFamilies {
		metrics := make([]*dto.Metric, m_num)
		for i, _ := range metrics {
			labelValue := fmt.Sprint(rand.Int63())
			value := rand.Float64()
			ts := time.Now().UnixNano()
			metrics[i] = &dto.Metric{
				Label: []*dto.LabelPair{
					&dto.LabelPair{
						Name:  &labelName,
						Value: &labelValue,
					},
				},
				Gauge: &dto.Gauge{
					Value: &value,
				},
				TimestampMs: &ts,
			}
		}
		metricName := fmt.Sprintf("metric%d", rand.Int63())
		metricFamilies[i] = &dto.MetricFamily{
			Name:   &metricName,
			Help:   &helpMsg,
			Type:   &metricType,
			Metric: metrics,
		}
	}

	buf := &bytes.Buffer{}
	enc := expfmt.NewEncoder(buf, expfmt.FmtText)
	for _, mf := range metricFamilies {
		enc.Encode(mf)
	}

	return buf
}
