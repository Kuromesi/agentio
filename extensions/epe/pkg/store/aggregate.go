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
	"slices"
	"sync"
	"sync/atomic"
)

type backendView = Batch
type queryRegistration struct {
	types        []Type
	dependencies []Type
	build        QueryBuilder
}

// Aggregate publishes immutable views from an ordered list of resource sources.
// Reads use atomic.Load; the mutex only serializes publication and registration.
type Aggregate struct {
	stores       []Store
	types        []Type
	mu           sync.Mutex
	backends     []backendView
	queries      []queryRegistration
	typeBuilders map[Type]TypeSnapshotBuilder
	inputs       map[Type][]TypeSnapshot
	current      atomic.Pointer[Snapshot]
	options      AggregateOptions
}

// NewAggregate uses a 10ms quiet window and a 50ms maximum batching delay.
func NewAggregate(stores ...Store) *Aggregate {
	return NewAggregateWithOptions(DefaultAggregateOptions(), stores...)
}

// NewAggregateWithOptions creates an initial view. Run starts change tracking;
// callers retain ownership of each backend's lifecycle.
func NewAggregateWithOptions(options AggregateOptions, stores ...Store) *Aggregate {
	a := &Aggregate{
		stores:       slices.Clone(stores),
		options:      options,
		typeBuilders: map[Type]TypeSnapshotBuilder{},
		inputs:       map[Type][]TypeSnapshot{},
	}
	for _, s := range stores {
		for _, typ := range s.Types() {
			if !slices.Contains(a.types, typ) {
				a.types = append(a.types, typ)
			}
		}
	}
	a.Refresh()
	return a
}

// Types returns a read-only list of the supported resource types.
func (a *Aggregate) Types() []Type { return a.types }

// Snapshot loads one immutable view for a request's related queries.
func (a *Aggregate) Snapshot() *Snapshot { return a.current.Load() }

// Ready reads publication readiness without querying or locking backends.
func (a *Aggregate) Ready() bool { return a.Snapshot().Ready() }

// Get reads the currently published view.
func (a *Aggregate) Get(key Key) (*Resource, error) { return a.Snapshot().Get(key) }

// List reads the currently published view; the returned slice is read-only.
func (a *Aggregate) List(typ Type) ([]Resource, error) { return a.Snapshot().List(typ) }

// ResourcesFor selects resources using a resource-specific immutable index.
func (a *Aggregate) ResourcesFor(typ Type, subject Subject) ([]Resource, error) {
	return a.Snapshot().ResourcesFor(typ, subject)
}

// RegisterQueries installs a builder before Run starts. One builder can expose
// multiple query types while sharing its index. Only the declared type snapshots
// may be used as dependencies; readiness is handled by the outer snapshot.
func (a *Aggregate) RegisterQueries(types, dependencies []Type, build QueryBuilder) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.queries = append(
		a.queries,
		queryRegistration{types: slices.Clone(types), dependencies: slices.Clone(dependencies), build: build},
	)
	a.refreshLocked(true)
}

// RegisterTypeSnapshot installs a type-specific builder before Run starts.
// It receives effective resources after source priority has been resolved.
func (a *Aggregate) RegisterTypeSnapshot(typ Type, build TypeSnapshotBuilder) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.typeBuilders[typ] = build
	a.refreshLocked(true)
}

// Refresh immediately publishes pending source changes, bypassing debounce.
// Fetch uses this path so a demanded resource is visible before returning.
func (a *Aggregate) Refresh() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked(false)
}

func (a *Aggregate) refreshLocked(force bool) {
	next := make([]backendView, len(a.stores))
	changed := force || len(a.backends) != len(a.stores) || a.current.Load() == nil
	for i, s := range a.stores {
		status := s.Status()
		if i < len(a.backends) && a.backends[i].Status == status {
			next[i] = a.backends[i]
			continue
		}
		changed = true
		next[i] = s.Read()
	}
	ready := true
	for _, backend := range next {
		ready = ready && backend.Ready
	}
	if current := a.current.Load(); current != nil && current.ready != ready {
		changed = true
	}
	if !changed {
		return
	}
	a.backends = next
	old := a.current.Load()
	view := a.merge(old, force)
	for _, registration := range a.queries {
		var previous Query
		if old != nil {
			previous = old.queries[registration.types[0]]
		}
		query := previous
		if force || query == nil || dependenciesChanged(old, view, registration.dependencies) {
			query = registration.build(view, previous)
		}
		for _, typ := range registration.types {
			view.queries[typ] = query
		}
	}
	a.publish(view)
}

func dependenciesChanged(old, current *Snapshot, types []Type) bool {
	if old == nil {
		return true
	}
	for _, typ := range types {
		if old.Type(typ) != current.Type(typ) {
			return true
		}
	}
	return false
}

func (a *Aggregate) merge(old *Snapshot, force bool) *Snapshot {
	view := &Snapshot{ready: true, types: map[Type]TypeSnapshot{}, queries: map[Type]Query{}}
	for _, backend := range a.backends {
		view.ready = view.ready && backend.Ready
	}
	for _, typ := range a.types {
		var sources []TypeSnapshot
		for _, backend := range a.backends {
			if source := backend.Snapshots[typ]; source != nil {
				sources = append(sources, source)
			}
		}
		var previous TypeSnapshot
		if old != nil {
			previous = old.Type(typ)
		}
		if !force && previous != nil && slices.Equal(a.inputs[typ], sources) {
			view.types[typ] = previous
			continue
		}
		a.inputs[typ] = sources
		var effective TypeSnapshot = &mergedTypeSnapshot{sources: sources}
		if len(sources) == 1 {
			effective = sources[0]
		}
		build := a.typeBuilders[typ]
		if build == nil {
			build = materializeType
		}
		view.types[typ] = build(effective, previous)
	}
	return view
}

func (a *Aggregate) publish(view *Snapshot) {
	old := a.current.Load()
	view.changed = make(chan struct{})
	a.current.Store(view)
	if old != nil {
		close(old.changed)
	}
}

// invalidate blocks new subject queries before an unhealthy source is rebuilt.
func (a *Aggregate) invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.current.Load()
	if !old.ready {
		return
	}
	next := *old
	next.ready = false
	a.publish(&next)
}

// Fetch explicitly retrieves from supporting sources in priority order, then
// publishes immediately and reads through the same precedence rules as Get.
func (a *Aggregate) Fetch(ctx context.Context, key Key) (*Resource, error) {
	for _, s := range a.stores {
		if !slices.Contains(s.Types(), key.Type) {
			continue
		}
		r, err := s.Fetch(ctx, key)
		if err != nil {
			return nil, err
		}
		if r != nil {
			a.Refresh()
			return a.Get(key)
		}
	}
	return nil, nil
}
