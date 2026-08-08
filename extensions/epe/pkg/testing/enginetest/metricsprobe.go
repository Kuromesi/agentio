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

package enginetest

import (
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"istio.io/istio/extensions/epe/pkg/metrics"
)

// metricsMu serializes tests that assert deltas on the process-wide
// metrics registry; parallel tests would otherwise race on shared
// counters.
var metricsMu sync.Mutex

// LockMetrics acquires the metrics mutex for the duration of the test.
// Call it first in any test that uses MetricProbe.
func LockMetrics(t testing.TB) {
	t.Helper()
	metricsMu.Lock()
	t.Cleanup(metricsMu.Unlock)
}

// MetricProbe records a baseline value of one counter series so tests can
// assert deltas despite cross-test accumulation on package-level metrics.
type MetricProbe struct {
	name     string
	labels   map[string]string
	baseline float64
}

// ProbeMetric snapshots the current value of the named counter series in
// the EPE registry. A series that has not been written yet
// reads as 0.
func ProbeMetric(t testing.TB, name string, labels map[string]string) *MetricProbe {
	t.Helper()
	p := &MetricProbe{name: name, labels: labels}
	p.baseline = p.value(t)
	return p
}

// Delta returns the change since the probe was created.
func (p *MetricProbe) Delta(t testing.TB) float64 {
	t.Helper()
	return p.value(t) - p.baseline
}

// RequireDelta asserts the change since the probe was created.
func (p *MetricProbe) RequireDelta(t testing.TB, want float64) {
	t.Helper()
	if got := p.Delta(t); got != want {
		t.Fatalf("metric %s%v delta = %v, want %v", p.name, p.labels, got, want)
	}
}

func (p *MetricProbe) value(t testing.TB) float64 {
	t.Helper()
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != p.name {
			continue
		}
		for _, m := range family.GetMetric() {
			if !labelsMatch(p.labels, m.GetLabel()) {
				continue
			}
			switch {
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(want map[string]string, got []*dto.LabelPair) bool {
	for key, value := range want {
		found := false
		for _, pair := range got {
			if pair.GetName() == key && pair.GetValue() == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
