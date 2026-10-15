// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gatewayagent

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func TestMetricsAggregateAndSurviveEnvoyFailure(t *testing.T) {
	var adminStatus atomic.Int64
	adminStatus.Store(http.StatusOK)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminStatus.Load() == -1 {
			w.Header().Set("Content-Length", "1000")
			if _, err := fmt.Fprint(w, "envoy_good 1\nenvoy_partial{"); err != nil {
				t.Error(err)
			}
			return
		}
		if adminStatus.Load() != http.StatusOK {
			w.WriteHeader(int(adminStatus.Load()))
			return
		}
		if r.URL.Path != "/stats/prometheus" || r.Header.Get("Accept-Encoding") == "gzip" {
			t.Error("unexpected admin request")
		}
		if _, err := fmt.Fprintln(
			w,
			"# TYPE envoy_http_downstream_rq_total counter\nenvoy_http_downstream_rq_total 7",
		); err != nil {
			t.Errorf("write admin fixture: %v", err)
		}
	}))
	host, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = host
	c.Proxy.AdminPort = int32(n)
	c.metrics = newAgentMetrics()
	c.metrics.certificateExpiry.Store(time.Now().Add(time.Hour).Unix())
	c.metrics.sdsNacks.Inc()
	for i, code := range []int{200, 503, 200, -1, 0} {
		adminStatus.Store(int64(code))
		closed := code == 0
		if closed {
			admin.Close()
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/stats/prometheus", nil)
		request.Header.Set("Accept", "application/openmetrics-text")
		request.Header.Set("Accept-Encoding", "gzip")
		proxyMetrics(c)(response, request)
		parser := expfmt.NewTextParser(model.UTF8Validation)
		if response.Header().Get("Content-Encoding") != "gzip" {
			t.Fatal("compression not negotiated")
		}
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		families, err := parser.TextToMetricFamilies(reader)
		closeResource(reader)
		if err != nil {
			t.Fatalf("invalid metrics: %v\n%s", err, response.Body.String())
		}
		if families["agentio_gateway_agent_sds_nacks_total"].Metric[0].Counter.GetValue() != 1 {
			t.Fatal("missing agent metrics")
		}
		failures := float64(1)
		if i == 0 {
			failures = 0
		}
		if i >= 3 {
			failures = float64(i - 1)
		}
		if families["agentio_gateway_agent_scrapes_total"].Metric[0].Counter.GetValue() != float64(i+1) {
			t.Fatal("incorrect total scrapes")
		}
		bySource := map[string]float64{}
		for _, metric := range families["agentio_gateway_agent_scrape_failures_total"].GetMetric() {
			if len(metric.Label) != 1 || metric.Label[0].GetName() != "type" {
				t.Fatal("missing scrape source label")
			}
			bySource[metric.Label[0].GetValue()] = metric.Counter.GetValue()
		}
		if len(bySource) != 2 || bySource["envoy"] != failures || bySource["agent"] != 0 {
			t.Fatalf("incorrect scrape failures: %v", bySource)
		}
		if families["agentio_gateway_agent_go_goroutines"] == nil {
			t.Fatal("missing Go runtime metrics")
		}
		if runtime.GOOS == "linux" && families["agentio_gateway_agent_process_open_fds"] == nil {
			t.Fatal("missing process metrics")
		}
		if families["agentio_gateway_agent_envoy_scrape_success"] != nil ||
			families["agentio_gateway_agent_envoy_scrape_failures_total"] != nil {
			t.Fatal("obsolete scrape metrics exported")
		}
		if response.Code != http.StatusOK {
			t.Fatal("Envoy scrape failure must not hide agent metrics")
		}
		if code == 200 && families["envoy_http_downstream_rq_total"].Metric[0].Counter.GetValue() != 7 {
			t.Fatal("missing Envoy metrics")
		}
	}
}

func TestADSObservationClosesOnce(t *testing.T) {
	m := newAgentMetrics()
	received, done := observeADS(context.Background(), m)
	received()
	received()
	if testutil.ToFloat64(m.adsConnected) != 1 {
		t.Fatal("double counted")
	}
	done()
	received()
	if testutil.ToFloat64(m.adsConnected) != 0 || testutil.ToFloat64(m.adsDisconnects) != 1 {
		t.Fatal("late response leaked gauge")
	}
	_, done = observeADS(context.Background(), m)
	done()
	if testutil.ToFloat64(m.adsFailures) != 1 {
		t.Fatal("missing connection failure")
	}
}

func TestLocalAdminRequest(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
			return
		}
		if r.Method != "GET" || r.URL.RawQuery != "filter=server" {
			t.Error("request not preserved")
		}
		if _, err := fmt.Fprint(w, "server.state: 0"); err != nil {
			t.Errorf("write admin fixture: %v", err)
		}
	}))
	defer admin.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"http://example.invalid/", "/redirect"} {
		if err := adminRequest(t.Context(), []string{"--port", port, "GET", path}, io.Discard, io.Discard); err == nil {
			t.Fatal("accepted remote request/redirect")
		}
	}
	if err := adminRequest(
		t.Context(),
		[]string{"--port", port, "GET", "/stats?filter=server"},
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
}

// The first chunk must reach the scraper before Envoy finishes producing metrics.
func TestMetricsStreamBeforeAdminCompletes(t *testing.T) {
	finish := make(chan struct{})
	chunk := strings.Repeat("envoy_test_metric 1\n", 4096)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, chunk); err != nil {
			t.Errorf("write metrics: %v", err)
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
		}
	}))
	defer admin.Close()
	defer close(finish)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP, c.Proxy.AdminPort, c.metrics = host, int32(n), nil
	reader, writer := io.Pipe()
	defer closeResource(reader)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer closeResource(writer)
		proxyMetrics(c)(&streamingMetricsWriter{HeaderMap: http.Header{}, Writer: writer},
			httptest.NewRequest("GET", "/stats/prometheus", nil))
	}()
	received := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(reader, make([]byte, len(chunk)))
		received <- err
	}()
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("metrics were buffered until the admin response completed")
	}
	// Cleanup releases both the upstream handler and any blocked downstream write.
	t.Cleanup(func() { <-done })
}

type streamingMetricsWriter struct {
	HeaderMap http.Header
	io.Writer
}

func (w *streamingMetricsWriter) Header() http.Header { return w.HeaderMap }
func (w *streamingMetricsWriter) WriteHeader(int)     {}

func TestMetricsLocalhostOnly(t *testing.T) {
	for _, path := range []string{"/metrics", "/stats/prometheus"} {
		for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234", "192.0.2.1:1234"} {
			for _, restricted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", path, remote, restricted), func(t *testing.T) {
					c := testConfig(t)
					c.MetricsLocalhostOnly = restricted
					c.metrics = newAgentMetrics()
					// A refused admin connection still exposes agent health to permitted scrapers.
					c.Proxy.AdminPort = int32(freePort(t))
					r := httptest.NewRequest("GET", path, nil)
					r.RemoteAddr = remote
					r.Header.Set("Accept-Encoding", "gzip")
					w := httptest.NewRecorder()
					proxyMetrics(c)(w, r)
					if restricted && strings.HasPrefix(remote, "192.") {
						if w.Code != http.StatusForbidden || w.Header().Get("Content-Encoding") != "" {
							t.Fatal("non-local scrape was not rejected before compression")
						}
						if testutil.ToFloat64(c.metrics.envoyScrapeFailures) != 0 {
							t.Fatal("rejected scrape reached admin")
						}
					} else if w.Code != http.StatusOK || w.Header().Get("Content-Encoding") != "gzip" {
						t.Fatal("permitted scraper could not read agent metrics")
					}
				})
			}
		}
	}
}

func TestMetricsScrapeTimeout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		header   string
		delay    time.Duration
		failures float64
	}{
		{name: "long scrape", header: "15", delay: 11 * time.Second},
		{name: "deadline", header: "0.05", delay: 5 * time.Second, failures: 1},
		{name: "no header"},
		{name: "invalid header", header: "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds") != tc.header ||
					r.UserAgent() != "Prometheus/test" ||
					r.URL.RawQuery != "filter=server" {
					t.Error("scrape headers or query were not forwarded")
				}
				select {
				case <-time.After(tc.delay):
				case <-r.Context().Done():
					return
				}
				if _, err := fmt.Fprintln(w, "envoy_fixture 1"); err != nil {
					t.Error(err)
				}
			}))
			defer admin.Close()
			c := testConfig(t)
			c.IP = "127.0.0.1"
			c.Proxy.AdminPort = int32(admin.Listener.Addr().(*net.TCPAddr).Port)
			c.metrics = newAgentMetrics()
			port := freePort(t)
			stop, _, err := serveStatusOn(proxyMetrics(c), port)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				fmt.Sprintf("http://127.0.0.1:%d/metrics?filter=server", port),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", tc.header)
			request.Header.Set("User-Agent", "Prometheus/test")
			client := &http.Client{Timeout: 20 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeResource(response.Body)
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK ||
				!strings.Contains(string(body), "agentio_gateway_agent_scrapes_total 1") {
				t.Fatal("scrape did not preserve Agent metrics")
			}
			if strings.Contains(string(body), "envoy_fixture 1") != (tc.failures == 0) ||
				testutil.ToFloat64(c.metrics.envoyScrapeFailures) != tc.failures {
				t.Fatal("scrape did not honor requested timeout")
			}
		})
	}
}

func TestMetricsScrapeCancellation(t *testing.T) {
	arrived := make(chan struct{})
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-r.Context().Done()
	}))
	defer admin.Close()
	c := testConfig(t)
	c.IP = "127.0.0.1"
	c.Proxy.AdminPort = int32(admin.Listener.Addr().(*net.TCPAddr).Port)
	c.metrics = newAgentMetrics()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, "GET", "/metrics", nil)
	r.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "60")
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyMetrics(c)(httptest.NewRecorder(), r)
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape ignored client cancellation")
	}
	if testutil.ToFloat64(c.metrics.envoyScrapeFailures) != 1 {
		t.Fatal("cancelled scrape failure not counted")
	}
}

type invalidAgentCollector struct{}

func (invalidAgentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("invalid_agent_fixture", "Invalid collection fixture.", nil, nil)
}

func (invalidAgentCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("invalid_agent_fixture", "Invalid collection fixture.", nil, nil), errors.New("collection failed"))
}

type agentMetricsErrorWriter struct{ http.ResponseWriter }

func (agentMetricsErrorWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 0, errors.New("metrics write failed")
}

func TestAgentMetricsExportFailure(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()
	for _, failure := range []string{"gather", "write"} {
		t.Run(failure, func(t *testing.T) {
			c := testConfig(t)
			c.IP = "127.0.0.1"
			c.Proxy.AdminPort = int32(admin.Listener.Addr().(*net.TCPAddr).Port)
			c.metrics = newAgentMetrics()
			response := httptest.NewRecorder()
			var writer http.ResponseWriter = response
			if failure == "gather" {
				c.metrics.registry.MustRegister(invalidAgentCollector{})
			} else {
				writer = agentMetricsErrorWriter{response}
			}
			proxyMetrics(c)(writer, httptest.NewRequest("GET", "/metrics", nil))
			if testutil.ToFloat64(c.metrics.agentScrapeFailures) != 1 ||
				testutil.ToFloat64(c.metrics.envoyScrapeFailures) != 0 {
				t.Fatal("Agent export failure attributed to wrong source")
			}
			if response.Code != http.StatusOK || response.Body.Len() != 0 {
				t.Fatal("Agent export error inserted a non-metrics HTTP error body")
			}
		})
	}
}
