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
	"maps"
	"reflect"
	"sort"

	"google.golang.org/protobuf/proto"
)

// TypeSnapshot is an immutable view of one resource type. Implementations use
// pointers, preserving identity while unchanged. Returned values are read-only.
// List may return a partial result with an error; callers must not ignore it.
// Get returns nil, nil for absence and must preserve source error semantics.
type TypeSnapshot interface {
	Get(name string) (*Resource, error)
	List() ([]Resource, error)
}

// TypeSnapshotBuilder builds a type's storage/index from effective resources,
// after source precedence. It may reuse previous; neither input may be mutated.
// With one source, effective is that source's original implementation.
type TypeSnapshotBuilder func(effective, previous TypeSnapshot) TypeSnapshot

// DefaultSnapshot provides map lookup and a name-sorted list for ordinary types.
// Custom snapshots may embed it, but are not required to use its representation.
type DefaultSnapshot struct {
	resources map[string]*Resource
	list      []Resource
	err       error
}

// NewDefaultSnapshot owns its map and slice. Resource values must be immutable.
func NewDefaultSnapshot(resources []Resource, err error) *DefaultSnapshot {
	return buildDefaultSnapshot(resources, err, nil)
}

// WithChanges publishes a new snapshot sharing unchanged Resource objects.
// Upserts must contain only changed resources; values remain immutable. The
// existing source error is retained. No changes returns the original snapshot.
func (s *DefaultSnapshot) WithChanges(upserts []Resource, removed []string) *DefaultSnapshot {
	if len(upserts) == 0 && len(removed) == 0 {
		return s
	}
	next := &DefaultSnapshot{resources: maps.Clone(s.resources), err: s.err}
	for _, name := range removed {
		delete(next.resources, name)
	}
	for _, resource := range upserts {
		next.resources[resource.Key.Name] = &resource
	}
	next.buildList()
	return next
}

// Get returns a resource by name, or the source error when absent.
func (s *DefaultSnapshot) Get(name string) (*Resource, error) {
	if r := s.resources[name]; r != nil {
		return r, nil
	}
	return nil, s.err
}

// List returns the read-only, name-sorted resources and any source error.
func (s *DefaultSnapshot) List() ([]Resource, error) { return s.list, s.err }

func buildDefaultSnapshot(resources []Resource, err error, previous *DefaultSnapshot) *DefaultSnapshot {
	next := &DefaultSnapshot{resources: make(map[string]*Resource, len(resources)), err: err}
	same := previous != nil && err == nil && previous.err == nil && len(resources) == len(previous.resources)
	for _, resource := range resources {
		r := &resource
		if previous != nil {
			if old := previous.resources[resource.Key.Name]; old != nil && equalValue(old.Value, resource.Value) {
				r = old
			} else {
				same = false
			}
		}
		next.resources[resource.Key.Name] = r
	}
	if same {
		return previous
	}
	next.buildList()
	return next
}

func (s *DefaultSnapshot) buildList() {
	s.list = make([]Resource, 0, len(s.resources))
	for _, r := range s.resources {
		s.list = append(s.list, *r)
	}
	sort.Slice(s.list, func(i, j int) bool { return s.list[i].Key.Name < s.list[j].Key.Name })
}

func equalValue(a, b any) bool {
	if pa, ok := a.(proto.Message); ok {
		pb, ok := b.(proto.Message)
		return ok && proto.Equal(pa, pb)
	}
	return reflect.DeepEqual(a, b)
}

// mergedTypeSnapshot applies source priority without requiring map storage.
// It is used only while building; the default builder materializes its result.
type mergedTypeSnapshot struct{ sources []TypeSnapshot }

func (s *mergedTypeSnapshot) Get(name string) (*Resource, error) {
	for _, source := range s.sources {
		r, err := source.Get(name)
		if err != nil || r != nil {
			return r, err
		}
	}
	return nil, nil
}

func (s *mergedTypeSnapshot) List() ([]Resource, error) {
	seen := map[string]bool{}
	var result []Resource
	for _, source := range s.sources {
		resources, err := source.List()
		for _, r := range resources {
			if !seen[r.Key.Name] {
				seen[r.Key.Name] = true
				result = append(result, r)
			}
		}
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func materializeType(effective, previous TypeSnapshot) TypeSnapshot {
	// A single backend already owns a complete type snapshot.
	switch effective.(type) {
	case *mergedTypeSnapshot:
		resources, err := effective.List()
		old, _ := previous.(*DefaultSnapshot)
		return buildDefaultSnapshot(resources, err, old)
	default:
		return effective
	}
}
