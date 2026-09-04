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

package krt

import (
	"sync"
	"testing"
	"time"
)

// captureFlush returns a flush function plus a getter that returns the
// concatenation of every batch the flush has seen.
func captureFlush[T any]() (flush func([]T), got func() [][]T) {
	var mu sync.Mutex
	var seen [][]T
	flush = func(batch []T) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]T, len(batch))
		copy(cp, batch)
		seen = append(seen, cp)
	}
	got = func() [][]T {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]T, len(seen))
		copy(out, seen)
		return out
	}
	return
}

func TestDebouncer_SingleEventFlushesAfterWindow(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	flush, got := captureFlush[int]()
	d := newDebouncer[int](20*time.Millisecond, 0, 16, flush, stop, "test")
	d.Start()

	d.Enqueue(1)

	deadline := time.After(500 * time.Millisecond)
	for {
		if batches := got(); len(batches) == 1 && len(batches[0]) == 1 && batches[0][0] == 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("never saw single flush; got=%v", got())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestDebouncer_BurstAggregatedIntoOneFlush(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	flush, got := captureFlush[int]()
	d := newDebouncer[int](30*time.Millisecond, 0, 16, flush, stop, "test")
	d.Start()

	for i := range 10 {
		d.Enqueue(i)
		time.Sleep(2 * time.Millisecond) // well under after window
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		batches := got()
		if len(batches) == 1 && len(batches[0]) == 10 {
			for i, v := range batches[0] {
				if v != i {
					t.Fatalf("order broken at idx %d: %v", i, batches[0])
				}
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("never saw single 10-event flush; got=%v", got())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestDebouncer_MaxDelayForcesFlush(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	flush, got := captureFlush[int]()
	// after=50ms, maxDelay=100ms. Producer keeps resetting after every 20ms.
	d := newDebouncer[int](50*time.Millisecond, 100*time.Millisecond, 16, flush, stop, "test")
	d.Start()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 20 {
			d.Enqueue(i)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// After ~100ms maxDelay should have fired even though after keeps resetting.
	deadline := time.After(300 * time.Millisecond)
	for {
		if batches := got(); len(batches) >= 1 {
			// First flush should have happened before producer finished.
			return
		}
		select {
		case <-deadline:
			t.Fatalf("maxDelay never fired; got=%v", got())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestDebouncer_StopDrainsPending(t *testing.T) {
	stop := make(chan struct{})

	flush, got := captureFlush[int]()
	d := newDebouncer[int](1*time.Hour, 0, 16, flush, stop, "test")
	d.Start()

	d.Enqueue(1)
	d.Enqueue(2)
	d.Enqueue(3)
	// Give the goroutine a chance to receive them before stopping.
	time.Sleep(20 * time.Millisecond)

	close(stop)

	deadline := time.After(500 * time.Millisecond)
	for {
		batches := got()
		if len(batches) == 1 && len(batches[0]) == 3 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("stop did not drain pending; got=%v", got())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestDebouncer_SyncedAfterFirstFlush(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	flush, _ := captureFlush[int]()
	d := newDebouncer[int](20*time.Millisecond, 0, 16, flush, stop, "test")
	d.Start()

	if d.HasSynced() {
		t.Fatalf("HasSynced true before any enqueue")
	}

	d.Enqueue(1)

	select {
	case <-d.Synced():
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Synced channel never closed after first flush")
	}
	if !d.HasSynced() {
		t.Fatalf("HasSynced false after Synced channel closed")
	}
}
