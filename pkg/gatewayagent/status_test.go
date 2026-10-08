// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package gatewayagent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func TestMetricsAggregateAndSurviveEnvoyFailure(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats/prometheus" || r.Header.Get("Accept-Encoding") == "gzip" {
			t.Error("unexpected admin request")
		}
		fmt.Fprintln(w, "# TYPE envoy_http_downstream_rq_total counter\nenvoy_http_downstream_rq_total 7")
	}))
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	n, _ := strconv.Atoi(port)
	c := testConfig(t)
	c.IP = host
	c.Proxy.AdminPort = int32(n)
	c.metrics = newAgentMetrics()
	c.metrics.certificateExpiry.Store(time.Now().Add(time.Hour).Unix())
	c.metrics.sdsNacks.Inc()
	for _, closed := range []bool{false, true} {
		if closed {
			admin.Close()
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/stats/prometheus", nil)
		request.Header.Set("Accept", "application/openmetrics-text")
		request.Header.Set("Accept-Encoding", "gzip")
		proxyMetrics(c)(response, request)
		parser := expfmt.NewTextParser(model.UTF8Validation)
		families, err := parser.TextToMetricFamilies(strings.NewReader(response.Body.String()))
		if err != nil {
			t.Fatalf("invalid metrics: %v\n%s", err, response.Body.String())
		}
		if families["agentio_gateway_agent_sds_nacks_total"].Metric[0].Counter.GetValue() != 1 {
			t.Fatal("missing agent metrics")
		}
		if !closed && families["envoy_http_downstream_rq_total"].Metric[0].Counter.GetValue() != 7 {
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
		fmt.Fprint(w, "server.state: 0")
	}))
	defer admin.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	for _, path := range []string{"http://example.invalid/", "/redirect"} {
		if err := adminRequest(t.Context(), []string{"--port", port, "GET", path}, io.Discard, io.Discard); err == nil {
			t.Fatal("accepted remote request/redirect")
		}
	}
	if err := adminRequest(t.Context(), []string{"--port", port, "GET", "/stats?filter=server"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
