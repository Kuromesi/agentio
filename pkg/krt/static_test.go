// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"fmt"
	"sync"
	"testing"
	"time"

	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/krt"
)

func TestStaticCollection(t *testing.T) {
	opts := testOptions(t)
	c := krt.NewMutableCollection[Named](nil, []Named{{"ns", "a"}}, opts.WithName("c")...)
	assert.Equal(t, c.Synced().HasSynced(), true, "should start synced")
	assert.Equal(t, c.List(), []Named{{"ns", "a"}})

	tracker := assert.NewTracker[string](t)
	c.RegisterBatch(BatchedTrackerHandler[Named](tracker), true)
	tracker.WaitOrdered("add/ns/a")

	c.UpdateObject(Named{"ns", "b"})
	tracker.WaitOrdered("add/ns/b")

	c.UpdateObject(Named{"ns", "b"})
	tracker.WaitOrdered("update/ns/b")

	tracker2 := assert.NewTracker[string](t)
	c.RegisterBatch(BatchedTrackerHandler[Named](tracker2), true)
	tracker2.WaitCompare(CompareUnordered("add/ns/a", "add/ns/b"))

	c.DeleteObject("ns/b")
	tracker.WaitOrdered("delete/ns/b")
}

func TestStaticCollection_DebounceBatchesUpdates(t *testing.T) {
	stop := test.NewStop(t)

	s := krt.NewMutableCollection[Named](nil, []Named{}, krt.WithStop(stop),
		krt.WithDebounce(30*time.Millisecond, 0))

	var mu sync.Mutex
	var batches [][]krt.Event[Named]
	s.RegisterBatch(func(events []krt.Event[Named]) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]krt.Event[Named], len(events))
		copy(cp, events)
		batches = append(batches, cp)
	}, false)

	for i := range 5 {
		s.UpdateObject(Named{Namespace: "ns", Name: fmt.Sprintf("p%d", i)})
		time.Sleep(2 * time.Millisecond)
	}

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(batches)
		total := 0
		for _, b := range batches {
			total += len(b)
		}
		mu.Unlock()
		if total >= 5 && n < 5 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("expected batched delivery; got %d batches totaling %d", n, total)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestStaticCollectionConditionalBatch(t *testing.T) {
	opts := testOptions(t)
	a := SimpleService{Named: Named{"ns", "a"}, IP: "old"}
	b := SimpleService{Named: Named{"ns", "b"}, IP: "old"}
	c := krt.NewMutableCollection(nil, []SimpleService{a, b}, opts.WithName("batch")...)
	index := krt.NewIndex(c.AsCollection(), "ip", func(s SimpleService) []string { return []string{s.IP} })
	batches := make(chan []krt.Event[SimpleService], 8)
	c.RegisterBatch(func(es []krt.Event[SimpleService]) { batches <- es }, false)
	a.IP = "new"
	added := SimpleService{Named: Named{"ns", "c"}, IP: "new"}
	c.ConditionalUpdateObjects(a, b, added)
	select {
	case es := <-batches:
		if len(es) != 2 {
			t.Fatalf("got %d events, want 2", len(es))
		}
		assert.Equal(t, len(index.Lookup("new")), 2)
		assert.Equal(t, index.Lookup("old"), []SimpleService{b})
	case <-time.After(time.Second):
		t.Fatal("missing batch")
	}
	late := make(chan []krt.Event[SimpleService], 8)
	c.RegisterBatch(func(es []krt.Event[SimpleService]) { late <- es }, false)
	c.ConditionalUpdateObjects(a, b, added)
	c.ConditionalUpdateObjects()
	// A subsequent real event establishes the ordering boundary without a timer.
	b.IP = "new"
	c.ConditionalUpdateObject(b)
	for _, events := range []chan []krt.Event[SimpleService]{batches, late} {
		select {
		case es := <-events:
			if len(es) != 1 || es[0].Latest().Name != "b" {
				t.Fatalf("unexpected replay/no-op batch: %v", es)
			}
		case <-time.After(time.Second):
			t.Fatal("missing subsequent event")
		}
	}
	assert.Equal(t, len(index.Lookup("new")), 3)
	assert.Equal(t, len(index.Lookup("old")), 0)
}
