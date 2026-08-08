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
package webhook

import (
	"github.com/prometheus/client_golang/prometheus"

	"istio.io/istio/extensions/epe/pkg/metrics"
)

var (
	DispatchedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epe_audit_webhook_dispatched_total",
			Help: "Audit webhook dispatch outcomes (post-render).",
		},
		[]string{"result"}, // success|http_error|transport_error|timeout
	)

	DroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epe_audit_webhook_dropped_total",
			Help: "Audit webhook events dropped before dispatch.",
		},
		[]string{"reason"}, // buffer_full|draining|stopped|shutdown_timeout|render_url|render_body|render_header|invalid_scheme|body_too_large
	)

	DurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "epe_audit_webhook_duration_seconds",
			Help:    "Audit webhook HTTP call duration.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		DispatchedTotal,
		DroppedTotal,
		DurationSeconds,
	)
}
