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

package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openkruise/agentio/pkg/model"
)

func TestDemandMetricsShareNamesAndReleaseWaiters(t *testing.T) {
	m := New()
	first := m.WaitStarted(model.WorkloadType, "private-pod")
	second := m.WaitStarted(model.WorkloadType, "private-pod")
	other := m.WaitStarted(model.SandboxType, "private-sandbox")
	if testutil.ToFloat64(m.demandWaiters.WithLabelValues("workload")) != 2 ||
		testutil.ToFloat64(m.demandPending.WithLabelValues("workload")) != 1 {
		t.Fatal("shared lookup was counted as two resources")
	}
	first()
	if testutil.ToFloat64(m.demandPending.WithLabelValues("workload")) != 1 {
		t.Fatal("resource removed before last waiter")
	}
	second()
	other()
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			stop := m.WaitStarted(model.WorkloadType, "private-pod")
			stop()
		})
	}
	group.Wait()
	if len(m.waiting) != 0 || testutil.ToFloat64(m.demandWaiters.WithLabelValues("workload")) != 0 ||
		testutil.ToFloat64(m.demandPending.WithLabelValues("workload")) != 0 {
		t.Fatal("wait accounting leaked")
	}
	m.DemandCompleted(model.WorkloadType, false, time.Millisecond, nil)
	m.DemandCompleted(model.WorkloadType, true, time.Second, context.DeadlineExceeded)
	m.RegisterCacheEntries(func() int { return 7 })
	response := httptest.NewRecorder()
	promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}).
		ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	for _, sample := range []string{
		`agentio_porter_demand_requests_total{path="immediate",resource_type="workload",result="success"} 1`,
		`agentio_porter_demand_requests_total{path="waited",resource_type="workload",result="timeout"} 1`,
		`agentio_porter_demand_duration_seconds_count{resource_type="workload",result="timeout"} 1`,
		`agentio_porter_demand_cache_entries 7`,
	} {
		if !strings.Contains(body, sample) {
			t.Errorf("missing %s", sample)
		}
	}
	if strings.Contains(body, "private-") ||
		strings.Contains(
			body,
			`agentio_porter_demand_duration_seconds_count{resource_type="workload",result="success"}`,
		) {
		t.Fatal("exposed resource name or observed a cache hit as discovery latency")
	}
}
