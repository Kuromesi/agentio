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

// Copyright Istio Authors
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
	"time"
)

// debouncer aggregates a stream of T values, calling flush with the
// accumulated slice when either the after-window has elapsed since the
// last Enqueue, or maxDelay has elapsed since the first un-flushed event.
//
// Append-only: events keep their arrival order; no key coalescing.
// Single goroutine: flush callback runs from the debouncer loop, so it
// must not block indefinitely.
type debouncer[T any] struct {
	after    time.Duration
	maxDelay time.Duration
	ch       chan T
	flush    func([]T)
	stop     <-chan struct{}
	name     string

	// synced is closed after the first non-empty flush. HasSynced/Synced
	// expose this so callers can wait for "the debouncer has delivered at
	// least one batch downstream".
	synced     chan struct{}
	syncedOnce sync.Once
}

func newDebouncer[T any](
	after, maxDelay time.Duration,
	bufSize int,
	flush func([]T),
	stop <-chan struct{},
	name string,
) *debouncer[T] {
	if bufSize <= 0 {
		bufSize = 1024
	}
	return &debouncer[T]{
		after:    after,
		maxDelay: maxDelay,
		ch:       make(chan T, bufSize),
		flush:    flush,
		stop:     stop,
		name:     name,
		synced:   make(chan struct{}),
	}
}

// Start spawns the goroutine that runs the debouncer loop.
func (d *debouncer[T]) Start() {
	go d.run()
}

// Synced returns a channel that is closed once the debouncer has flushed
// at least one non-empty batch.
func (d *debouncer[T]) Synced() <-chan struct{} {
	return d.synced
}

// HasSynced reports whether the debouncer has flushed at least one
// non-empty batch.
func (d *debouncer[T]) HasSynced() bool {
	select {
	case <-d.synced:
		return true
	default:
		return false
	}
}

// Enqueue submits a value to the debouncer. Returns immediately if stop
// has been closed; otherwise blocks until the value is accepted by the
// bounded channel. Values accepted before stop are guaranteed to be
// flushed via the stop-drain path in run().
func (d *debouncer[T]) Enqueue(v T) {
	select {
	case <-d.stop:
	case d.ch <- v:
	}
}

func (d *debouncer[T]) run() {
	var debounceTimer *time.Timer
	var maxTimer <-chan time.Time
	var pending []T

	debounceC := func() <-chan time.Time {
		if debounceTimer != nil {
			return debounceTimer.C
		}
		return nil
	}

	doFlush := func() {
		if len(pending) > 0 {
			log.Debugf("%v debouncer flushed %d events", d.name, len(pending))
			batch := pending
			pending = nil
			d.flush(batch)
			d.syncedOnce.Do(func() { close(d.synced) })
		}
		if debounceTimer != nil {
			debounceTimer.Stop()
			debounceTimer = nil
		}
		maxTimer = nil
	}

	for {
		select {
		case v := <-d.ch:
			pending = append(pending, v)
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.NewTimer(d.after)
			if maxTimer == nil && d.maxDelay > 0 {
				maxTimer = time.After(d.maxDelay)
			}
		case <-debounceC():
			doFlush()
		case <-maxTimer:
			doFlush()
		case <-d.stop:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			// Drain anything still buffered in d.ch before final flush.
		drainLoop:
			for {
				select {
				case v := <-d.ch:
					pending = append(pending, v)
				default:
					break drainLoop
				}
			}
			doFlush()
			return
		}
	}
}
