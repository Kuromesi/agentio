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

package xds

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// Watches registers native protocols only. Authorization is never consumed.
func Watches() []xdsclient.Watch {
	return []xdsclient.Watch{
		{
			TypeURL:  model.WorkloadType,
			Wildcard: true,
			Validate: func(v *anypb.Any) error { return v.UnmarshalTo(&workload.Workload{}) },
		},
		{
			TypeURL:  model.TrafficPolicyType,
			Wildcard: true,
			Validate: func(v *anypb.Any) error { return v.UnmarshalTo(&sec.TrafficPolicy{}) },
		},
	}
}

// Source is the Delta ADS client surface needed by this backend.
type Source interface {
	Snapshot() xdsclient.Snapshot
	Demand(context.Context, string, string) (*anypb.Any, error)
	Observe(...string) (<-chan struct{}, bool)
}

// Store exposes native xDS resources through EPE's resource interface.
type Store struct {
	source  Source
	mu      sync.Mutex
	cached  xdsclient.Snapshot
	batch   store.Batch
	decoded xdsclient.Snapshot
}

var _ store.Store = (*Store)(nil)

// New wraps an xDS source; the caller owns its lifecycle.
func New(source Source) *Store { return &Store{source: source} }

// Types lists the native models served by this backend.
func (s *Store) Types() []store.Type { return []store.Type{store.Workload, store.TrafficPolicy} }

// Status observes synchronization and changes without copying or decoding resources.
func (s *Store) Status() store.Status {
	changed, ready := s.source.Observe(model.WorkloadType, model.TrafficPolicyType)
	return store.Status{Ready: ready, Changed: changed}
}

// Keep one owned raw snapshot per publication so per-resource queries do not
// repeatedly clone the entire client cache. Decoding returns fresh values.
func (s *Store) snapshot() xdsclient.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() xdsclient.Snapshot {
	changed, _ := s.source.Observe(model.WorkloadType, model.TrafficPolicyType)
	if s.cached.Resources == nil || s.cached.Changed != changed {
		s.cached = s.source.Snapshot()
	}
	return s.cached
}

// Read decodes one consistent xDS publication on the aggregate update path.
func (s *Store) Read() store.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.snapshotLocked()
	batch := store.Batch{
		Status:    store.Status{Ready: true, Changed: snapshot.Changed},
		Snapshots: map[store.Type]store.TypeSnapshot{},
	}
	for _, typ := range s.Types() {
		wire := wireType(typ)
		batch.Ready = batch.Ready && snapshot.Synced[wire]
		batch.Snapshots[typ] = decodeType(snapshot, s.decoded, typ, s.batch.Snapshots[typ])
	}

	s.decoded, s.batch = snapshot, batch
	return batch
}

func decodeType(snapshot, prior xdsclient.Snapshot, typ store.Type, previous store.TypeSnapshot) store.TypeSnapshot {
	wire := wireType(typ)
	if !snapshot.Synced[wire] {
		if previous != nil && !prior.Synced[wire] {
			return previous
		}
		return store.NewDefaultSnapshot(nil, fmt.Errorf("%s xDS is not synchronized", typ))
	}
	old, _ := previous.(*store.DefaultSnapshot)
	raw := prior.Resources[wire]
	if old == nil || !prior.Synced[wire] {
		old, raw = store.NewDefaultSnapshot(nil, nil), nil
	} else if _, err := old.List(); err != nil {
		// A failed decode did not publish a complete type. Rebuild it on recovery.
		old, raw = store.NewDefaultSnapshot(nil, nil), nil
	}
	var upserts []store.Resource
	for name, value := range snapshot.Resources[wire] {
		if proto.Equal(raw[name], value) {
			continue
		}
		resource, err := decode(store.Key{Type: typ, Name: name}, value)
		if err != nil {
			return store.NewDefaultSnapshot(nil, err)
		}
		upserts = append(upserts, *resource)
	}
	var removed []string
	for name := range raw {
		if _, found := snapshot.Resources[wire][name]; !found {
			removed = append(removed, name)
		}
	}
	return old.WithChanges(upserts, removed)
}

// get retrieves a cached resource without initiating a network request.
func (s *Store) get(key store.Key) (*store.Resource, error) {
	typeURL := wireType(key.Type)
	if typeURL == "" {
		return nil, nil
	}
	snapshot := s.snapshot()
	if !snapshot.Synced[typeURL] {
		return nil, fmt.Errorf("%s xDS is not synchronized", key.Type)
	}
	return decode(key, snapshot.Resources[typeURL][key.Name])
}

// Fetch explicitly subscribes to a missing resource. Context bounds the wait.
func (s *Store) Fetch(ctx context.Context, key store.Key) (*store.Resource, error) {
	typeURL := wireType(key.Type)
	if typeURL == "" {
		return nil, nil
	}
	resource, err := s.get(key)
	if err != nil || resource != nil {
		return resource, err
	}
	value, err := s.source.Demand(ctx, typeURL, key.Name)
	if errors.Is(err, xdsclient.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decode(key, value)
}

func wireType(typ store.Type) string {
	switch typ {
	case store.Workload:
		return model.WorkloadType
	case store.TrafficPolicy:
		return model.TrafficPolicyType
	default:
		return ""
	}
}

func decode(key store.Key, value *anypb.Any) (*store.Resource, error) {
	if value == nil {
		return nil, nil
	}
	var message proto.Message
	switch key.Type {
	case store.Workload:
		message = &workload.Workload{}
	case store.TrafficPolicy:
		message = &sec.TrafficPolicy{}
	}
	if err := value.UnmarshalTo(message); err != nil {
		return nil, fmt.Errorf("decode %s %q: %w", key.Type, key.Name, err)
	}
	return &store.Resource{Key: key, Value: message}, nil
}
