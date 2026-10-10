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

package store

import (
	"context"
	"testing"
	"time"
)

func startAggregate(t *testing.T, a *Aggregate) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func awaitPublication(t *testing.T, before *Snapshot) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	select {
	case <-before.Changed():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func (s *memoryStore) setReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ready
	close(s.changed)
	s.changed = make(chan struct{})
}

func TestDebounceCoalescesBurst(t *testing.T) {
	backend := memory(Workload)
	a := NewAggregateWithOptions(
		AggregateOptions{Debounce: 40 * time.Millisecond, MaxDelay: 150 * time.Millisecond},
		backend,
	)
	startAggregate(t, a)
	before := a.Snapshot()
	key := Key{Type: Workload, Name: "pod"}
	for i := range 10 {
		backend.put(Resource{Key: key, Value: i})
	}
	time.Sleep(10 * time.Millisecond)
	if a.Snapshot() != before {
		t.Fatal("ordinary burst bypassed debounce")
	}
	awaitPublication(t, before)
	current := a.Snapshot()
	time.Sleep(60 * time.Millisecond)
	if a.Snapshot() != current {
		t.Fatal("burst published more than once")
	}
	resource, err := a.Get(key)
	if err != nil || resource.Value != 9 {
		t.Fatal(resource, err)
	}
}

func TestDebounceHasMaximumDelay(t *testing.T) {
	backend := memory(Workload)
	a := NewAggregateWithOptions(AggregateOptions{Debounce: time.Second, MaxDelay: 30 * time.Millisecond}, backend)
	startAggregate(t, a)
	before := a.Snapshot()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(3 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				backend.put(Resource{Key: Key{Type: Workload, Name: "pod"}, Value: i})
			}
		}
	}()
	awaitPublication(t, before)
	cancel()
	<-done
}

func TestReadinessAndFetchBypassDebounce(t *testing.T) {
	backend := memory(Workload)
	a := NewAggregateWithOptions(AggregateOptions{Debounce: time.Hour, MaxDelay: time.Hour}, backend)
	startAggregate(t, a)
	before := a.Snapshot()
	backend.setReady(false)
	awaitPublication(t, before)
	if a.Ready() {
		t.Fatal("readiness loss was delayed")
	}
	backend.setReady(true)
	// Invalidation and materialization may publish separately; wait for recovery.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		view := a.Snapshot()
		if view.Ready() {
			break
		}
		select {
		case <-view.Changed():
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	key := Key{Type: Workload, Name: "fetched"}
	backend.pending = &Resource{Key: key, Value: "ready"}
	resource, err := a.Fetch(t.Context(), key)
	if err != nil || resource == nil || resource.Value != "ready" {
		t.Fatal(resource, err)
	}
	if resource, err := a.Get(key); err != nil || resource == nil {
		t.Fatal("fetch not published", err)
	}
}
