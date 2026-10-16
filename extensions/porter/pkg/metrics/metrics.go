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

// Package metrics exposes Porter's CONNECT processing and demand discovery metrics.
package metrics

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

var durationBuckets = []float64{.0005, .001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2, 4, 8}

// Metrics owns the registry for one Porter instance.
type Metrics struct {
	Registry        *prometheus.Registry
	connectDuration *prometheus.HistogramVec
	connectRequests *prometheus.CounterVec
	connectInflight *prometheus.GaugeVec
	demandDuration  *prometheus.HistogramVec
	demandRequests  *prometheus.CounterVec
	demandWaiters   *prometheus.GaugeVec
	demandPending   *prometheus.GaugeVec
	mu              sync.Mutex
	waiting         map[resourceKey]int
}

type resourceKey struct {
	typ  string
	name string
}

// New creates a registry with CONNECT, demand, Go runtime and process collectors.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		waiting:  make(map[resourceKey]int),
		connectDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "agentio_porter_connect_duration_seconds",
				Help:    "CONNECT processing from received headers through response send completion.",
				Buckets: durationBuckets,
			},
			[]string{"protocol", "result"},
		),
		connectRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "agentio_porter_connect_requests_total",
				Help: "Completed CONNECT processing attempts.",
			},
			[]string{"protocol", "result"},
		),
		connectInflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "agentio_porter_connect_inflight",
				Help: "CONNECT requests currently being processed.",
			},
			[]string{"protocol"},
		),
		demandDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "agentio_porter_demand_duration_seconds",
				Help:    "Demand lookup duration for calls that had to wait for discovery; excludes immediate cache results.",
				Buckets: durationBuckets,
			},
			[]string{"resource_type", "result"},
		),
		demandRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "agentio_porter_demand_requests_total",
				Help: "Completed demand lookups by immediate or waited path and result.",
			},
			[]string{"resource_type", "path", "result"},
		),
		demandWaiters: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "agentio_porter_demand_waiters",
				Help: "Demand calls waiting for a usable resource.",
			},
			[]string{"resource_type"},
		),
		demandPending: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "agentio_porter_demand_pending_resources",
				Help: "Distinct resource names with waiting demand calls.",
			},
			[]string{"resource_type"},
		),
	}
	m.Registry.MustRegister(
		m.connectDuration,
		m.connectRequests,
		m.connectInflight,
		m.demandDuration,
		m.demandRequests,
		m.demandWaiters,
		m.demandPending,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	for _, protocol := range []string{"tcp", "udp"} {
		m.connectInflight.WithLabelValues(protocol)
	}
	for _, typ := range []string{"workload", "sandbox"} {
		m.demandWaiters.WithLabelValues(typ)
		m.demandPending.WithLabelValues(typ)
	}
	return m
}

// RegisterCacheEntries exposes the current number of retained demand leases.
func (m *Metrics) RegisterCacheEntries(size func() int) {
	m.Registry.MustRegister(
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "agentio_porter_demand_cache_entries",
				Help: "Retained demand-cache leases across resource types; zero when the retention cache is disabled.",
			},
			func() float64 { return float64(size()) },
		),
	)
}

// ConnectStarted records a newly accepted CONNECT processing attempt.
func (m *Metrics) ConnectStarted(protocol string) { m.connectInflight.WithLabelValues(protocol).Inc() }

// ConnectCompleted records the final outcome and releases the in-flight count.
func (m *Metrics) ConnectCompleted(protocol string, denied bool, duration time.Duration, err error) {
	result := outcome(err)
	if result == "not_found" {
		result = "error"
	}
	if result == "success" {
		result = "allow"
		if denied {
			result = "deny"
		}
	}
	m.connectInflight.WithLabelValues(protocol).Dec()
	m.connectRequests.WithLabelValues(protocol, result).Inc()
	m.connectDuration.WithLabelValues(protocol, result).Observe(duration.Seconds())
}

// WaitStarted tracks callers separately from the distinct names they share.
// Resource names are held only while waiting and never become metric labels.
func (m *Metrics) WaitStarted(typ, name string) func() {
	label := resourceType(typ)
	key := resourceKey{typ, name}
	m.mu.Lock()
	if m.waiting[key] == 0 {
		m.demandPending.WithLabelValues(label).Inc()
	}
	m.waiting[key]++
	m.demandWaiters.WithLabelValues(label).Inc()
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.waiting[key]--
		if m.waiting[key] == 0 {
			delete(m.waiting, key)
			m.demandPending.WithLabelValues(label).Dec()
		}
		m.demandWaiters.WithLabelValues(label).Dec()
	}
}

// DemandCompleted records immediate and waited lookups separately.
func (m *Metrics) DemandCompleted(typ string, waited bool, duration time.Duration, err error) {
	label, result, path := resourceType(typ), outcome(err), "immediate"
	if waited {
		path = "waited"
		m.demandDuration.WithLabelValues(label, result).Observe(duration.Seconds())
	}
	m.demandRequests.WithLabelValues(label, path, result).Inc()
}

func resourceType(typ string) string {
	switch typ {
	case model.WorkloadType:
		return "workload"
	case model.SandboxType:
		return "sandbox"
	default:
		return "other"
	}
}

func outcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
		return "timeout"
	case errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled:
		return "canceled"
	case errors.Is(err, xdsclient.ErrNotFound):
		return "not_found"
	default:
		return "error"
	}
}
