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

// Package registry connects source collections and their observed identities.
package registry

import (
	"slices"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// Source pairs compiler inputs with the raw source state that produced them.
// Replacing or combining inputs must also replace or combine this state.
type Source[T any] struct {
	krt.Collection[T]
	Registry *SourceRegistry
}

// SourceObject is implemented by model inputs that can be used directly as sources.
type SourceObject interface {
	SourceKey() model.ResourceKey
	GetSourceIdentity() model.SourceIdentity
}

// NewSource uses model inputs as the source of truth. Adapters with asynchronous
// projections supply a Registry over their raw inputs instead.
func NewSource[T SourceObject](collection krt.Collection[T]) *Source[T] {
	return &Source[T]{
		Collection: collection,
		Registry: TrackSources(collection, "model-source-keys",
			func(obj T) []model.ResourceKey { return []model.ResourceKey{obj.SourceKey()} },
			func(obj T) model.SourceIdentity { return obj.GetSourceIdentity() }),
	}
}

// SourceEvents adds event-driven invalidation to source queries. Callbacks carry
// keys to recheck; concurrent recreation can make a notified key present again.
// Different source streams may invoke the callback concurrently.
type SourceEvents interface {
	model.SourceReader
	RegisterDeletes(func([]model.ResourceKey)) func()
}

// SourceRegistry combines source readers without copying their state into an
// asynchronously maintained cache. Construct it before serving queries.
type SourceRegistry struct {
	sources []SourceEvents
}

// NewSourceRegistry composes sources in priority order, matching KRT joins.
func NewSourceRegistry(sources ...SourceEvents) *SourceRegistry {
	return &SourceRegistry{sources: slices.Clone(sources)}
}

// Lookup returns the first present source, including unresolved conflicts.
func (r *SourceRegistry) Lookup(key model.ResourceKey) (model.SourceIdentity, bool) {
	for _, source := range r.sources {
		if identity, found := source.Lookup(key); found {
			// Match KRT JoinCollection's first-source-wins ordering.
			return identity, true
		}
	}
	return model.SourceIdentity{}, false
}

// RegisterDeletes subscribes to source invalidations and returns an unregister function.
func (r *SourceRegistry) RegisterDeletes(notify func([]model.ResourceKey)) func() {
	unregister := make([]func(), 0, len(r.sources))
	for _, source := range r.sources {
		unregister = append(unregister, source.RegisterDeletes(notify))
	}
	return func() {
		for _, stop := range unregister {
			stop()
		}
	}
}

// JoinSources keeps source observation and model collection composition together.
func JoinSources[T any](sources []*Source[T], opts ...krt.CollectionOption) *Source[T] {
	collections := make([]krt.Collection[T], 0, len(sources))
	readers := make([]SourceEvents, 0, len(sources))
	for _, source := range sources {
		collections = append(collections, source.Collection)
		readers = append(readers, source.Registry)
	}
	return &Source[T]{
		Collection: krt.JoinCollection(collections, opts...),
		Registry:   NewSourceRegistry(readers...),
	}
}

// TrackSources indexes raw inputs by their canonical delivery or compiler key.
// KRT updates the index with the cache, before asynchronous event delivery and
// debounce. Only key and identity extraction are specific to a source adapter.
// The index name must uniquely identify this key mapping within the collection.
func TrackSources[T any](collection krt.Collection[T], name string, keys func(T) []model.ResourceKey,
	identity func(T) model.SourceIdentity,
) *SourceRegistry {
	return NewSourceRegistry(&indexedSource[T]{
		collection: collection,
		index:      krt.NewIndex(collection, name, keys),
		keys:       keys,
		identity:   identity,
	})
}

type indexedSource[T any] struct {
	collection krt.Collection[T]
	index      krt.Index[model.ResourceKey, T]
	keys       func(T) []model.ResourceKey
	identity   func(T) model.SourceIdentity
}

func (s *indexedSource[T]) Lookup(key model.ResourceKey) (model.SourceIdentity, bool) {
	objects := s.index.Lookup(key)
	switch len(objects) {
	case 0:
		return model.SourceIdentity{}, false
	case 1:
		return s.identity(objects[0]), true
	default:
		return model.SourceIdentity{}, true
	}
}

func (s *indexedSource[T]) RegisterDeletes(notify func([]model.ResourceKey)) func() {
	registration := s.collection.RegisterBatch(func(events []krt.Event[T]) {
		removed := make(map[model.ResourceKey]struct{})
		for _, event := range events {
			if event.Old == nil {
				continue
			}
			var current []model.ResourceKey
			if event.New != nil {
				current = s.keys(*event.New)
			}
			for _, key := range s.keys(*event.Old) {
				if !slices.Contains(current, key) {
					removed[key] = struct{}{}
				}
			}
		}
		if len(removed) == 0 {
			return
		}
		keys := make([]model.ResourceKey, 0, len(removed))
		for key := range removed {
			keys = append(keys, key)
		}
		notify(keys)
	}, false)
	return registration.UnregisterHandler
}
