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
	"fmt"
	"io"
	"math"
	"strconv"
	"sync/atomic"
)

// histogram is a minimal fixed-bucket Prometheus histogram backed by atomic counters.
type histogram struct {
	name, help string
	bounds     []float64
	counts     []atomic.Uint64
	sum        atomic.Uint64 // float64 bits
	total      atomic.Uint64
}

func newHistogram(name, help string, bounds []float64) *histogram {
	return &histogram{
		name:   name,
		help:   help,
		bounds: bounds,
		counts: make([]atomic.Uint64, len(bounds)),
	}
}

func (h *histogram) observe(value float64) {
	for index, bound := range h.bounds {
		if value <= bound {
			h.counts[index].Add(1)
		}
	}
	h.total.Add(1)
	// CAS loop on the float64 bits accumulates the sum without a mutex.
	for {
		current := h.sum.Load()
		updated := math.Float64bits(math.Float64frombits(current) + value)
		if h.sum.CompareAndSwap(current, updated) {
			return
		}
	}
}

func (h *histogram) write(writer io.Writer, labels string) {
	h.writeAs(writer, h.name, h.help, labels)
}

func (h *histogram) writeAs(writer io.Writer, name, help, labels string) {
	fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for index, bound := range h.bounds {
		fmt.Fprintf(writer, "%s_bucket{%sle=\"%s\"} %d\n",
			name, labels, strconv.FormatFloat(bound, 'g', -1, 64), h.counts[index].Load())
	}
	fmt.Fprintf(writer, "%s_bucket{%sle=\"+Inf\"} %d\n", name, labels, h.total.Load())
	fmt.Fprintf(writer, "%s_sum{%s} %g\n", name, trimTrailingComma(labels), math.Float64frombits(h.sum.Load()))
	fmt.Fprintf(writer, "%s_count{%s} %d\n", name, trimTrailingComma(labels), h.total.Load())
}

func trimTrailingComma(labels string) string {
	if len(labels) > 0 && labels[len(labels)-1] == ',' {
		return labels[:len(labels)-1]
	}
	return labels
}

// latencyBuckets spans the range a control-plane push actually occupies: a
// sub-millisecond incremental recompute at one end, a multi-second full-cluster
// compile at the other.
var latencyBuckets = []float64{
	0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// Legacy pilot_* boundaries match Agentio exactly so mixed-version histogram
// aggregation remains mathematically valid during rolling upgrades.
var legacyPushLatencyBuckets = []float64{0.01, 0.1, 1, 3, 5, 10, 20, 30}

var legacyProxyLatencyBuckets = []float64{0.1, 0.5, 1, 3, 5, 10, 20, 30}

// sizeBuckets spans resource counts in a single response.
var sizeBuckets = []float64{1, 5, 25, 100, 500, 2_500, 10_000, 50_000}

// byteSizeBuckets retain the important Agentio dashboard boundaries: 10KB,
// 1MB, the default 4MB gRPC limit, 10MB, and 40MB.
var byteSizeBuckets = []float64{1, 10_000, 1_000_000, 4_000_000, 10_000_000, 40_000_000}
