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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
		success, failures := float64(0), float64(1)
		if code == 200 {
			success = 1
		}
		if i == 0 {
			failures = 0
		}
		if i >= 3 {
			failures = float64(i - 1)
		}
		if families["agentio_gateway_agent_envoy_scrape_success"].Metric[0].Gauge.GetValue() != success ||
			families["agentio_gateway_agent_envoy_scrape_failures_total"].Metric[0].Counter.GetValue() != failures {
			t.Fatal("incorrect scrape health metrics")
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
