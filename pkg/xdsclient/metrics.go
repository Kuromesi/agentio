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

// Package-local metrics are registered only when Config.MetricsRegisterer is set.
package xdsclient

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

type clientMetrics struct {
	connected    prometheus.GaugeFunc
	waitDuration *prometheus.HistogramVec
	waiters      *prometheus.GaugeVec
}

func newClientMetrics(c *Client) *clientMetrics {
	m := &clientMetrics{
		connected: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "agentio_xds_client_connected",
			Help: "Whether the ADS stream is open; does not imply resource synchronization or readiness.",
		}, func() float64 {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.connected {
				return 1
			}
			return 0
		}),
		waitDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "agentio_xds_client_demand_wait_duration_seconds",
			Help:    "Time demand calls spent waiting for a resource, including reconnection; excludes immediate results.",
			Buckets: []float64{.0005, .001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2, 4, 8},
		}, []string{"resource_type", "result"}),
		waiters: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "agentio_xds_client_demand_waiters",
			Help: "Number of demand calls currently waiting for a resource.",
		}, []string{"resource_type"}),
	}
	for _, watch := range c.cfg.Watches {
		m.waiters.WithLabelValues(watch.TypeURL)
	}
	return m
}

// Register the three metrics together so a duplicate registration leaves no partial state.
func (m *clientMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.connected.Describe(ch)
	m.waitDuration.Describe(ch)
	m.waiters.Describe(ch)
}

func (m *clientMetrics) Collect(ch chan<- prometheus.Metric) {
	m.connected.Collect(ch)
	m.waitDuration.Collect(ch)
	m.waiters.Collect(ch)
}

func demandResult(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	default:
		return "error"
	}
}
