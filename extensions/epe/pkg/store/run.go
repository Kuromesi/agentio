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
	"sync"
	"time"
)

// AggregateOptions bounds batching of ordinary resource updates. A zero quiet
// window publishes immediately. Durations exclude snapshot construction time.
type AggregateOptions struct {
	Debounce time.Duration
	MaxDelay time.Duration
}

// DefaultAggregateOptions coalesces bursts without postponing steady updates indefinitely.
func DefaultAggregateOptions() AggregateOptions {
	return AggregateOptions{Debounce: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}
}

type sourceChange struct {
	ready bool
}

// Run tracks source changes until cancellation. Readiness loss and recovery
// bypass debounce; ordinary updates are bounded by the quiet and maximum timers.
func (a *Aggregate) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	events := make(chan sourceChange, len(a.stores))
	for _, source := range a.stores {
		workers.Add(1)
		go func(source Store) {
			defer workers.Done()
			watchSource(ctx, source, events)
		}(source)
	}
	var quiet, maximum *time.Timer
	var quietC, maximumC <-chan time.Time
	stop := func() {
		if quiet != nil {
			quiet.Stop()
		}
		if maximum != nil {
			maximum.Stop()
		}
		quietC, maximumC = nil, nil
	}
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-events:
			ready := a.Ready()
			if !event.ready || !ready || a.options.Debounce <= 0 {
				if !event.ready {
					a.invalidate()
				}
				a.Refresh()
				stop()
				continue
			}
			if quietC == nil {
				quiet = time.NewTimer(a.options.Debounce)
				quietC = quiet.C
				maximum = time.NewTimer(a.options.MaxDelay)
				maximumC = maximum.C
			} else {
				quiet.Reset(a.options.Debounce)
			}
		case <-quietC:
			a.Refresh()
			stop()
		case <-maximumC:
			a.Refresh()
			stop()
		}
	}
}

func watchSource(ctx context.Context, source Store, events chan<- sourceChange) {
	for {
		status := source.Status()
		select {
		case events <- sourceChange{ready: status.Ready}:
		case <-ctx.Done():
			return
		}
		select {
		case <-status.Changed:
		case <-ctx.Done():
			return
		}
	}
}
