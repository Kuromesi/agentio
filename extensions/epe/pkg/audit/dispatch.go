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
package audit

import (
	"context"
	"errors"
	"sync"
	"time"
)

type DropReason string

const (
	DropBufferFull      DropReason = "buffer_full"
	DropDraining        DropReason = "draining"
	DropStopped         DropReason = "stopped"
	DropShutdownTimeout DropReason = "shutdown_timeout"
)

// DropObserver observes an audit item that could not be queued.
// It may be nil.
type DropObserver func(DropReason)

type dispatcherState uint8

const (
	stateAccepting dispatcherState = iota
	stateDraining
	stateStopped
)

// defaultDrainTimeout bounds the best-effort shutdown allowance. Tests may
// replace the per-dispatcher field with a shorter duration.
const defaultDrainTimeout = 5 * time.Second

var errDispatcherAlreadyStarted = errors.New("audit dispatcher can only be started once")

// Dispatcher is the shared bounded async delivery primitive used by the
// audit domain: a bounded channel fed by non-blocking Enqueue calls and
// drained by a fixed-size worker pool. It satisfies the runnable.Runnable
// contract via Start.
//
// On ctx cancellation the dispatcher stops admission, gives accepted work a
// bounded interval to finish under a detached work context, then cancels the
// workers and drops any work they did not start. The channel is never closed:
// Enqueue stays safe for the lifetime of the process, including long after
// Start has returned.
//
// That last property is load-bearing, not incidental. Producers here are
// ext-proc streams, and runnable.Group hands the same ctx to every member at
// once — so the dispatcher stops while the gRPC server is still in
// GracefulStop draining in-flight streams. Those streams emit their audit
// events on the way out, deliberately under context.WithoutCancel, which puts
// their Enqueue calls strictly after this dispatcher has stopped. Closing the
// queue on stop would turn that ordering into a "send on closed channel"
// panic, and an unrecovered panic on the stream goroutine kills the whole
// process mid-drain. Late items are dropped instead; losing an audit event
// costs less than losing every in-flight request.
type Dispatcher[T any] struct {
	name    string
	ch      chan T
	workers int
	handle  func(context.Context, T)
	onDrop  DropObserver

	mu      sync.Mutex
	state   dispatcherState
	started bool

	// pending counts items accepted by Enqueue but not yet fully handled
	// (queued + in-flight). Used by Drain.
	pending int64
	idle    chan struct{}

	drainTimeout time.Duration
}

// NewDispatcher constructs a Dispatcher. buffer < 0 clamps to 0 and
// workers <= 0 clamps to 1; consumer-facing defaults (e.g. 4096 entries or
// 96 workers) remain the wrapper's responsibility. onDrop may be nil, in
// which case drops are unobserved.
func NewDispatcher[T any](name string, buffer, workers int, handle func(context.Context, T), onDrop DropObserver) *Dispatcher[T] {
	if buffer < 0 {
		buffer = 0
	}
	if workers <= 0 {
		workers = 1
	}
	idle := make(chan struct{})
	close(idle)
	return &Dispatcher[T]{
		name:         name,
		ch:           make(chan T, buffer),
		workers:      workers,
		handle:       handle,
		onDrop:       onDrop,
		idle:         idle,
		drainTimeout: defaultDrainTimeout,
	}
}

// Name returns the identifier the dispatcher was constructed with.
func (d *Dispatcher[T]) Name() string { return d.name }

// Cap returns the queue capacity.
func (d *Dispatcher[T]) Cap() int { return cap(d.ch) }

// Len returns the number of currently queued items.
func (d *Dispatcher[T]) Len() int { return len(d.ch) }

// Workers returns the worker pool size.
func (d *Dispatcher[T]) Workers() int { return d.workers }

func (d *Dispatcher[T]) addPendingLocked() {
	if d.pending == 0 {
		d.idle = make(chan struct{})
	}
	d.pending++
}

func (d *Dispatcher[T]) settleLocked() {
	d.pending--
	if d.pending < 0 {
		panic("audit dispatcher pending count became negative")
	}
	if d.pending == 0 {
		close(d.idle)
	}
}

func (d *Dispatcher[T]) beginDrain() {
	d.mu.Lock()
	if d.state == stateAccepting {
		d.state = stateDraining
	}
	d.mu.Unlock()
}

func (d *Dispatcher[T]) markStopped() {
	d.mu.Lock()
	d.state = stateStopped
	d.mu.Unlock()
}

func (d *Dispatcher[T]) notifyDrop(reason DropReason) {
	if d.onDrop != nil {
		d.onDrop(reason)
	}
}

// Enqueue is non-blocking: when the queue is full the value is dropped and
// the drop observer (when set) is called. A nil receiver or nil channel is a
// no-op so uninitialised dispatchers never panic on the request path.
func (d *Dispatcher[T]) Enqueue(v T) {
	if d == nil || d.ch == nil {
		return
	}
	var reason DropReason
	d.mu.Lock()
	switch d.state {
	case stateDraining:
		reason = DropDraining
	case stateStopped:
		reason = DropStopped
	default:
		d.addPendingLocked()
		select {
		case d.ch <- v:
		default:
			d.settleLocked()
			reason = DropBufferFull
		}
	}
	d.mu.Unlock()
	if reason != "" {
		d.notifyDrop(reason)
	}
}

// Drain is a snapshot barrier: it blocks until the current pending generation
// becomes idle, or ctx is done. An enqueue that starts after Drain captures an
// already-idle generation is not included. Callers that require global
// quiescence must stop or join producers before calling Drain.
func (d *Dispatcher[T]) Drain(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	idle := d.idle
	d.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleOne runs the handler and settles the pending count, keeping the
// steady-state and drain loops symmetrical.
func (d *Dispatcher[T]) handleOne(ctx context.Context, v T) {
	defer func() {
		d.mu.Lock()
		d.settleLocked()
		d.mu.Unlock()
	}()
	d.handle(ctx, v)
}

// Start runs the worker pool until ctx is cancelled, drains accepted work for
// a bounded interval, and returns nil. It implements runnable.Runnable. A
// Dispatcher is one-shot; every call after the first returns an error.
func (d *Dispatcher[T]) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return errDispatcherAlreadyStarted
	}
	d.started = true
	d.mu.Unlock()

	workCtx, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()

	var wg sync.WaitGroup
	for i := 0; i < d.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.workerLoop(workCtx)
		}()
	}
	<-ctx.Done()
	d.beginDrain()
	drainCtx, cancelDrain := context.WithTimeout(context.WithoutCancel(ctx), d.drainTimeout)
	drainErr := d.Drain(drainCtx)
	cancelDrain()
	cancelWork()
	wg.Wait()
	if drainErr != nil {
		d.purge(DropShutdownTimeout)
	}
	d.markStopped()
	return nil
}

// workerLoop consumes accepted work until the detached work context is
// canceled. The first cancellation check prevents a worker from starting
// another queued item after its current handler returns from cancellation.
func (d *Dispatcher[T]) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case v := <-d.ch:
			d.handleOne(ctx, v)
		}
	}
}

// purge settles queued work that no worker started before shutdown expired.
// Workers have exited before this runs, so each remaining channel entry is
// owned exclusively by the purge loop.
func (d *Dispatcher[T]) purge(reason DropReason) {
	for {
		select {
		case <-d.ch:
			d.mu.Lock()
			d.settleLocked()
			d.mu.Unlock()
			d.notifyDrop(reason)
		default:
			return
		}
	}
}
