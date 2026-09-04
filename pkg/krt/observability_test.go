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

package krt_test

import (
	"sync/atomic"
	"testing"

	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/krt"
)

// The recompute counter is how operators confirm from production that a
// collection recomputes only what its dependencies demand, so the counter
// itself must track transform executions exactly.
func TestCollectionCountsTransformExecutions(t *testing.T) {
	opts := testOptions(t)
	source := krt.NewStaticCollection[Named](nil, []Named{{"ns", "a"}}, opts.WithName("source")...)
	var calls atomic.Int64
	derived := krt.NewCollection(source, func(_ krt.HandlerContext, in Named) *Named {
		calls.Add(1)
		return &Named{Namespace: in.Namespace, Name: "derived-" + in.Name}
	}, opts.WithName("derived")...)

	tracker := assert.NewTracker[string](t)
	derived.Register(TrackerHandler[Named](tracker))
	tracker.WaitOrdered("add/ns/derived-a")
	if got := derived.Metadata()["recomputeTotal"]; got != uint64(1) {
		t.Fatalf("recomputeTotal = %v, want 1", got)
	}
	assert.Equal(t, calls.Load(), int64(1))

	source.UpdateObject(Named{"ns", "b"})
	tracker.WaitOrdered("add/ns/derived-b")
	if got := derived.Metadata()["recomputeTotal"]; got != uint64(2) {
		t.Fatalf("recomputeTotal = %v, want 2", got)
	}
	assert.Equal(t, calls.Load(), int64(2))
}

func TestWithoutTransformInstrumentationSkipsCounting(t *testing.T) {
	opts := testOptions(t)
	source := krt.NewStaticCollection[Named](nil, []Named{{"ns", "a"}}, opts.WithName("source")...)
	var calls atomic.Int64
	derived := krt.NewCollection(source, func(_ krt.HandlerContext, in Named) *Named {
		calls.Add(1)
		return &Named{Namespace: in.Namespace, Name: "derived-" + in.Name}
	}, append(opts.WithName("derived"), krt.WithoutTransformInstrumentation())...)

	tracker := assert.NewTracker[string](t)
	derived.Register(TrackerHandler[Named](tracker))
	tracker.WaitOrdered("add/ns/derived-a")
	// Transforms still run; only the accounting is skipped.
	assert.Equal(t, calls.Load(), int64(1))
	if got := derived.Metadata()["recomputeTotal"]; got != uint64(0) {
		t.Fatalf("recomputeTotal = %v, want 0 with instrumentation disabled", got)
	}
}
