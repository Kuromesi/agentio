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

package agentio

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"istio.io/istio/pkg/kube/krt"
	"k8s.io/apimachinery/pkg/util/wait"
)

type pollingSyncer struct {
	name         string
	pollFunc     func(ctx context.Context) bool
	pollInterval time.Duration
	synced       *atomic.Bool
}

func (p *pollingSyncer) WaitUntilSynced(stop <-chan struct{}) bool {
	ctx := wait.ContextForChannel(stop)
	err := wait.PollUntilContextCancel(ctx, p.pollInterval, true, func(ctx context.Context) (bool, error) {
		if p.pollFunc(ctx) {
			p.synced.Store(true)
			return true, nil
		}
		log.Debugf("waiting for %s to sync", p.name)
		return false, nil
	})
	if err == nil {
		log.Infof("%s synced", p.name)
		return true
	}
	return false
}

func (p *pollingSyncer) HasSynced() bool {
	return p.synced.Load()
}

func NewPollingSyncer(name string, pollFunc func(ctx context.Context) bool, pollInterval time.Duration) krt.Syncer {
	return &pollingSyncer{
		name:         name,
		pollFunc:     pollFunc,
		pollInterval: pollInterval,
		synced:       &atomic.Bool{},
	}
}

// delayedSingleton wraps a krt.Singleton that is created lazily after a precondition is met.
// Before the inner singleton is ready, all methods return safe zero values.
// Once the syncer reports synced, the callback is invoked to create the real singleton,
// and all subsequent calls delegate to it. Event handlers registered before the inner
// singleton is ready are replayed once it becomes available.
type delayedSingleton[T any] struct {
	mu       sync.RWMutex
	inner    krt.Singleton[T]
	syncer   krt.Syncer
	callback func() krt.Singleton[T]
	stop     <-chan struct{}
	ready    chan struct{}

	// handlers registered before inner is ready
	pendingHandlersMu sync.Mutex
	pendingHandlers   []func(o krt.Event[T])
}

func (d *delayedSingleton[T]) getInner() krt.Singleton[T] {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.inner
}

// Get implements [krt.Singleton].
func (d *delayedSingleton[T]) Get() *T {
	if inner := d.getInner(); inner != nil {
		return inner.Get()
	}
	return nil
}

// Register implements [krt.Singleton].
func (d *delayedSingleton[T]) Register(f func(o krt.Event[T])) krt.HandlerRegistration {
	if inner := d.getInner(); inner != nil {
		return inner.Register(f)
	}
	d.pendingHandlersMu.Lock()
	d.pendingHandlers = append(d.pendingHandlers, f)
	d.pendingHandlersMu.Unlock()
	return noopHandlerRegistration{}
}

// AsCollection implements [krt.Singleton].
func (d *delayedSingleton[T]) AsCollection() krt.Collection[T] {
	return &delayedCollection[T]{d}
}

// Metadata implements [krt.Singleton].
func (d *delayedSingleton[T]) Metadata() krt.Metadata {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().Metadata()
	}
	return nil
}

func (d *delayedSingleton[T]) run() {
	go func() {
		if !d.syncer.WaitUntilSynced(d.stop) {
			return
		}
		inner := d.callback()

		d.mu.Lock()
		d.inner = inner
		d.mu.Unlock()
		close(d.ready)

		d.pendingHandlersMu.Lock()
		handlers := d.pendingHandlers
		d.pendingHandlers = nil
		d.pendingHandlersMu.Unlock()

		for _, f := range handlers {
			inner.Register(f)
		}
	}()
}

func NewDelayedSingleton[T any](syncer krt.Syncer, callback func() krt.Singleton[T], stop <-chan struct{}) krt.Singleton[T] {
	s := &delayedSingleton[T]{
		callback: callback,
		syncer:   syncer,
		stop:     stop,
		ready:    make(chan struct{}),
	}
	s.run()
	return s
}

// delayedCollection adapts delayedSingleton to the krt.Collection interface.
type delayedCollection[T any] struct {
	*delayedSingleton[T]
}

func (d *delayedCollection[T]) GetKey(k string) *T {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().GetKey(k)
	}
	return nil
}

func (d *delayedCollection[T]) List() []T {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().List()
	}
	return nil
}

func (d *delayedCollection[T]) Register(f func(o krt.Event[T])) krt.HandlerRegistration {
	return d.delayedSingleton.Register(f)
}

func (d *delayedCollection[T]) RegisterBatch(f func(o []krt.Event[T]), runExistingState bool) krt.HandlerRegistration {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().RegisterBatch(f, runExistingState)
	}
	d.pendingHandlersMu.Lock()
	d.pendingHandlers = append(d.pendingHandlers, func(o krt.Event[T]) {
		f([]krt.Event[T]{o})
	})
	d.pendingHandlersMu.Unlock()
	return noopHandlerRegistration{}
}

func (d *delayedCollection[T]) Metadata() krt.Metadata {
	return d.delayedSingleton.Metadata()
}

// HasSynced returns true only after the inner singleton is created and synced.
func (d *delayedCollection[T]) HasSynced() bool {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().HasSynced()
	}
	return false
}

// WaitUntilSynced blocks until the inner singleton is ready and synced.
func (d *delayedCollection[T]) WaitUntilSynced(stop <-chan struct{}) bool {
	select {
	case <-d.ready:
	case <-stop:
		return false
	}
	return d.getInner().AsCollection().WaitUntilSynced(stop)
}

type noopHandlerRegistration struct{}

func (noopHandlerRegistration) WaitUntilSynced(<-chan struct{}) bool { return true }
func (noopHandlerRegistration) HasSynced() bool                      { return true }
func (noopHandlerRegistration) UnregisterHandler()                   {}

var _ krt.Singleton[any] = &delayedSingleton[any]{}
var _ krt.Collection[any] = &delayedCollection[any]{}
