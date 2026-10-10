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

import "fmt"

// Subject identifies the sandbox/workload and attributes needed by typed queries.
type Subject struct {
	Namespace string
	Name      string
	IP        string
	Labels    map[string]string
}

// Query is an immutable, resource-specific index built after source precedence.
// Returned resources and slices are read-only.
type Query interface {
	ResourcesFor(Type, Subject) ([]Resource, error)
}

// QueryBuilder builds a typed query index on the update path. The previous index
// may be reused for unchanged dependencies. It must never be mutated.
type QueryBuilder func(current *Snapshot, previous Query) Query

// Snapshot is an immutable aggregate view. Hold one for all related queries.
// Its indexes and resource values must not be mutated after publication.
type Snapshot struct {
	ready   bool
	types   map[Type]TypeSnapshot
	queries map[Type]Query
	changed chan struct{}
}

// Ready reports whether this snapshot's sources are synchronized.
func (s *Snapshot) Ready() bool { return s.ready }

// Changed closes when a newer aggregate snapshot is published.
func (s *Snapshot) Changed() <-chan struct{} { return s.changed }

// Type returns a type's snapshot, including any type-specific query extensions.
// An unsupported type returns nil.
func (s *Snapshot) Type(typ Type) TypeSnapshot { return s.types[typ] }

// Get delegates to the effective type snapshot.
func (s *Snapshot) Get(key Key) (*Resource, error) {
	if view := s.types[key.Type]; view != nil {
		return view.Get(key.Name)
	}
	return nil, nil
}

// List delegates to the type snapshot; returned values are read-only.
func (s *Snapshot) List(typ Type) ([]Resource, error) {
	if view := s.types[typ]; view != nil {
		return view.List()
	}
	return nil, nil
}

// Query returns the resource-specific index for this view.
func (s *Snapshot) Query(typ Type) Query { return s.queries[typ] }

// ResourcesFor uses a registered index, never a generic resource scan.
func (s *Snapshot) ResourcesFor(typ Type, subject Subject) ([]Resource, error) {
	if !s.ready {
		return nil, fmt.Errorf("resource store is not synchronized")
	}
	query := s.queries[typ]
	if query == nil {
		return nil, fmt.Errorf("no query registered for %s", typ)
	}
	return query.ResourcesFor(typ, subject)
}

// MissingResource asks the caller to explicitly Fetch a referenced resource.
type MissingResource struct{ Key Key }

func (e *MissingResource) Error() string {
	return fmt.Sprintf("%s %q unavailable", e.Key.Type, e.Key.Name)
}
