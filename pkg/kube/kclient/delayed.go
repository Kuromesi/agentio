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

package kclient

import (
	"sync"
	"sync/atomic"

	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// StartableInformer is an informer whose backing factory can be started after
// event handlers and indexes have been registered.
type StartableInformer[T controllers.ComparableObject] interface {
	Informer[T]
	Start(stop <-chan struct{})
}

type activeInformer[T controllers.ComparableObject] struct {
	Informer[T]
	start     func(stop <-chan struct{})
	startOnce sync.Once
}

func (a *activeInformer[T]) Start(stop <-chan struct{}) {
	a.startOnce.Do(func() { a.start(stop) })
}

// delayedInformer starts as an empty, synced-after-CRD-discovery informer and
// atomically installs the typed informer if the CRD is present now or appears
// later.
type delayedInformer[T controllers.ComparableObject] struct {
	active  atomic.Pointer[activeInformer[T]]
	watcher kube.CrdWatcher

	mu       sync.Mutex
	handlers []delayedHandler
	indexes  []*delayedIndex[T]
	stop     <-chan struct{}
}

type delayedHandler struct {
	handler      cache.ResourceEventHandler
	registration *delayedHandlerRegistration
}

type delayedHandlerRegistration struct {
	hasSynced atomic.Pointer[func() bool]
	inner     atomic.Pointer[cache.ResourceEventHandlerRegistration]
}

func (r *delayedHandlerRegistration) HasSynced() bool {
	if synced := r.hasSynced.Load(); synced != nil {
		return (*synced)()
	}
	return false
}

type delayedIndex[T any] struct {
	name    string
	inner   atomic.Pointer[RawIndexer]
	extract func(T) []string
}

func (d *delayedIndex[T]) Lookup(key string) []any {
	if index := d.inner.Load(); index != nil {
		return (*index).Lookup(key)
	}
	return nil
}

// NewDelayedInformer installs the typed List/Watch after the CRD is discovered.
func NewDelayedInformer[T controllers.ComparableObject](
	client kube.Client,
	resource schema.GroupVersionResource,
	filter Filter,
) StartableInformer[T] {
	registration := registrationFor[T](client)
	if registration.Resource != resource {
		panic("delayed informer resource does not match its registered type")
	}
	return NewDelayedInformerFor[T](client, registration, filter)
}

// NewDelayedInformerFor is the external-API variant of NewDelayedInformer.
func NewDelayedInformerFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) StartableInformer[T] {
	if client == nil || client.CrdWatcher() == nil {
		panic("NewDelayedInformer called without a CRD watcher-enabled kube.Client")
	}
	resource := registration.Resource
	delayed := &delayedInformer[T]{
		watcher: client.CrdWatcher(),
	}
	build := func(<-chan struct{}) {
		delayed.set(newFilteredFor[T](client, registration, filter))
		log.Info("resource is ready; building client", "resource", resource.GroupResource())
	}
	if client.CrdWatcher().KnownOrCallback(resource, build) {
		build(nil)
	} else {
		log.Debug("resource is not ready; building delayed client", "resource", resource.GroupResource())
	}
	return delayed
}

func (d *delayedInformer[T]) set(active *activeInformer[T]) {
	if active == nil {
		return
	}
	d.mu.Lock()
	if d.active.Load() != nil {
		d.mu.Unlock()
		return
	}
	for _, pending := range d.handlers {
		registration := active.AddEventHandler(pending.handler)
		pending.registration.inner.Store(&registration)
		pending.registration.hasSynced.Store(ptr.Of(registration.HasSynced))
	}
	d.handlers = nil
	for _, pending := range d.indexes {
		index := active.Index(pending.name, pending.extract)
		pending.inner.Store(&index)
	}
	d.indexes = nil
	d.active.Store(active)
	stop := d.stop
	d.mu.Unlock()
	if stop != nil {
		active.Start(stop)
	}
}

func (d *delayedInformer[T]) Start(stop <-chan struct{}) {
	d.mu.Lock()
	d.stop = stop
	active := d.active.Load()
	d.mu.Unlock()
	if active != nil {
		active.Start(stop)
	}
}

func (d *delayedInformer[T]) Get(name, namespace string) T {
	if active := d.active.Load(); active != nil {
		return active.Get(name, namespace)
	}
	return ptr.Empty[T]()
}

func (d *delayedInformer[T]) List(namespace string, selector klabels.Selector) []T {
	if active := d.active.Load(); active != nil {
		return active.List(namespace, selector)
	}
	return nil
}

func (d *delayedInformer[T]) AddEventHandler(handler cache.ResourceEventHandler) cache.ResourceEventHandlerRegistration {
	if active := d.active.Load(); active != nil {
		return active.AddEventHandler(handler)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if active := d.active.Load(); active != nil {
		return active.AddEventHandler(handler)
	}
	registration := &delayedHandlerRegistration{}
	registration.hasSynced.Store(ptr.Of(d.watcher.HasSynced))
	d.handlers = append(d.handlers, delayedHandler{
		handler:      handler,
		registration: registration,
	})
	return registration
}

func (d *delayedInformer[T]) HasSynced() bool {
	if active := d.active.Load(); active != nil {
		return active.HasSynced()
	}
	return d.watcher.HasSynced()
}

func (d *delayedInformer[T]) HasSyncedIgnoringHandlers() bool {
	if active := d.active.Load(); active != nil {
		return active.HasSyncedIgnoringHandlers()
	}
	return d.watcher.HasSynced()
}

func (d *delayedInformer[T]) ShutdownHandler(registration cache.ResourceEventHandlerRegistration) {
	if delayed, ok := registration.(*delayedHandlerRegistration); ok {
		if inner := delayed.inner.Load(); inner != nil {
			if active := d.active.Load(); active != nil {
				active.ShutdownHandler(*inner)
			}
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, pending := range d.handlers {
			if pending.registration == delayed {
				d.handlers = append(d.handlers[:i], d.handlers[i+1:]...)
				return
			}
		}
		return
	}
	if active := d.active.Load(); active != nil {
		active.ShutdownHandler(registration)
	}
}

func (d *delayedInformer[T]) ShutdownHandlers() {
	d.mu.Lock()
	d.handlers = nil
	active := d.active.Load()
	d.mu.Unlock()
	if active != nil {
		active.ShutdownHandlers()
	}
}

func (d *delayedInformer[T]) Index(name string, extract func(T) []string) RawIndexer {
	if active := d.active.Load(); active != nil {
		return active.Index(name, extract)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if active := d.active.Load(); active != nil {
		return active.Index(name, extract)
	}
	index := &delayedIndex[T]{
		name:    name,
		extract: extract,
	}
	d.indexes = append(d.indexes, index)
	return index
}
