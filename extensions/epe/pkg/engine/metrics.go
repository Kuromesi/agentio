// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package engine

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/metrics"
)

// Phase labels for filter metrics. They name the dispatch point, not the
// ext_proc message. Values are stable so existing dashboards keep working.
const (
	phaseRequestHeaders = "request_headers"
	// The value differs from the phase name for compatibility with existing
	// dashboards.
	phaseRequestBody     = "body_finalize"
	phaseResponseHeaders = "response_headers"
	phaseResponseBody    = "response_body"
)

// pluginCallsTotal counts every filter invocation the dispatch path makes,
// labelled by the outcome the framework observed. Metric and label names
// are stable for existing dashboards.
var pluginCallsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "epe_plugin_calls_total",
		Help: "Total plugin invocations by plugin, phase and observed outcome.",
	},
	[]string{"plugin", "phase", "outcome"},
)

// pluginDurationSeconds measures how long each filter invocation takes.
var pluginDurationSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "epe_plugin_duration_seconds",
		Help: "Plugin invocation latency by plugin and phase.",
		// 2s is deliberate: for a filter whose cost is an outbound credential
		// or webhook call, the interesting range is 1s–5s. 4.5s straddles the
		// default budget so "near the limit" is distinguishable from
		// "cancelled".
		Buckets: []float64{.0005, .001, .005, .01, .05, .1, .5, 1, 2, 4.5, 5, 10},
	},
	[]string{"plugin", "phase"},
)

func init() {
	metrics.Registry.MustRegister(pluginCallsTotal, pluginDurationSeconds)
}

// outcome is the low-cardinality classification of one filter return. It is
// an index rather than a string so the counter children can be resolved once
// and looked up by position.
type outcome uint8

const (
	outcomeContinue outcome = iota
	outcomeImmediate
	outcomeMutate
	outcomeNeedBody
	outcomeError
	numOutcomes
)

// outcomeLabels are the metric label values, stable for existing dashboards.
var outcomeLabels = [numOutcomes]string{
	outcomeContinue:  "continue",
	outcomeImmediate: "immediate",
	outcomeMutate:    "mutate",
	// The value differs from the outcome name for compatibility with existing
	// dashboards.
	outcomeNeedBody: "record",
	outcomeError:    "error",
}

func (o outcome) String() string { return outcomeLabels[o] }

// filterMetrics is the pre-resolved metric state for one (filter, phase)
// pair. Resolving a Prometheus child costs a label-set hash plus a lookup in
// a mutex-guarded map; the set of pairs a given Engine can emit is fixed at
// construction, so doing it there turns two such lookups per filter
// invocation into none.
type filterMetrics struct {
	filter   string
	phase    string
	duration prometheus.Observer
	calls    [numOutcomes]prometheus.Counter
}

// newFilterMetrics resolves every child this (filter, phase) pair can touch.
// Pre-resolving all five outcomes is what keeps the hot path lookup-free —
// the alternative would be resolving the counter lazily on first use of each
// outcome, which reintroduces the guarded map lookup on the error paths.
func newFilterMetrics(name, phase string) *filterMetrics {
	m := &filterMetrics{
		filter:   name,
		phase:    phase,
		duration: pluginDurationSeconds.WithLabelValues(name, phase),
	}
	for o := outcome(0); o < numOutcomes; o++ {
		m.calls[o] = pluginCallsTotal.WithLabelValues(name, phase, o.String())
	}
	return m
}

// observe records one invocation.
func (m *filterMetrics) observe(elapsed time.Duration, o outcome) {
	m.duration.Observe(elapsed.Seconds())
	m.calls[o].Inc()
}

// regMetrics holds one registration's pre-resolved metrics, one per
// dispatched phase. Named fields rather than a map: every call site knows
// its phase statically, so this resolves to a field offset instead of a
// hash lookup.
type regMetrics struct {
	requestHeaders  *filterMetrics
	requestBody     *filterMetrics
	responseHeaders *filterMetrics
	responseBody    *filterMetrics
}

// buildMetrics pre-resolves the children for every registration across the
// phases it actually declares. Parallel to regs, so regIdx indexes both.
// Undeclared phases stay nil on purpose: no phantom zero-valued series on
// /metrics for (filter, phase) pairs that cannot happen, and a dispatch to
// an undeclared phase panics loudly instead of counting silently.
func buildMetrics(regs []filter.Registration) []regMetrics {
	out := make([]regMetrics, len(regs))
	for i, reg := range regs {
		if reg.Phases&filter.PhaseRequestHeaders != 0 {
			out[i].requestHeaders = newFilterMetrics(reg.Name, phaseRequestHeaders)
		}
		if reg.Phases&filter.PhaseRequestBody != 0 {
			out[i].requestBody = newFilterMetrics(reg.Name, phaseRequestBody)
		}
		if reg.Phases&filter.PhaseResponseHeaders != 0 {
			out[i].responseHeaders = newFilterMetrics(reg.Name, phaseResponseHeaders)
		}
		if reg.Phases&filter.PhaseResponseBody != 0 {
			out[i].responseBody = newFilterMetrics(reg.Name, phaseResponseBody)
		}
	}
	return out
}
