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
	"sort"
	"sync"

	"istio.io/istio/pkg/util/sets"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

var log = agentlog.New("xds")

// Publication is the result of atomically committing a snapshot change.
// Snapshot is the exact last-known-good state after the attempted publication.
type Publication struct {
	Changed  bool
	Snapshot model.ResourceSet
}

// Store publishes immutable resource snapshots and notifies interested subscribers.
type Store struct {
	mu          sync.RWMutex
	current     model.ResourceSet
	subscribers map[uint64]*subscriber
	// subscribersByType indexes subscribers by watched type.
	subscribersByType map[string]map[uint64]*subscriber
	nextID            uint64
}

// New creates a store with an initial snapshot and no subscribers.
func New(initial model.ResourceSet) *Store {
	return &Store{
		current:           initial,
		subscribers:       make(map[uint64]*subscriber),
		subscribersByType: make(map[string]map[uint64]*subscriber),
	}
}

// Snapshot returns the current immutable publication.
func (s *Store) Snapshot() model.ResourceSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Replace atomically installs a snapshot and notifies subscribers of effective changes.
func (s *Store) Replace(snapshot model.ResourceSet) Publication {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.current
	changes := before.Diff(snapshot)
	if len(changes) == 0 {
		return Publication{Snapshot: s.current}
	}
	s.current = snapshot
	s.notifyLocked(updateBetween(before, snapshot, changes))
	return Publication{Changed: true, Snapshot: snapshot}
}

// Apply publishes a compiled KRT batch without listing or rebuilding the full
// resource graph. Multiple changes for the same key collapse to their final
// value before the immutable snapshot is updated.
func (s *Store) Apply(changes []model.ResourceChange) (Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	coalesced := coalesceChanges(changes)
	if len(coalesced) == 0 {
		return Publication{Snapshot: s.current}, nil
	}
	before := s.current
	next, changed, err := before.Apply(coalesced)
	if err != nil || !changed {
		return Publication{Snapshot: before}, err
	}
	effective := make([]model.ResourceChange, 0, len(coalesced))
	for _, requested := range coalesced {
		oldResource, hadOld := before.Get(requested.Key)
		newResource, hasNew := next.Get(requested.Key)
		if hadOld && hasNew && oldResource.Hash == newResource.Hash {
			continue
		}
		change := model.ResourceChange{Key: requested.Key}
		if hadOld {
			oldCopy := oldResource
			change.Old = &oldCopy
		}
		if hasNew {
			newCopy := newResource
			change.New = &newCopy
		}
		effective = append(effective, change)
	}
	if len(effective) == 0 {
		return Publication{Snapshot: before}, nil
	}
	s.current = next
	s.notifyLocked(updateBetween(before, next, effective))
	return Publication{Changed: true, Snapshot: next}, nil
}

// Notify wakes subscribers when a dynamic resource outside the immutable
// snapshot (for example an on-demand SDS certificate) changes.
func (s *Store) Notify() {
	s.mu.Lock()
	s.notifyLocked(Update{
		version:    s.current.Version(),
		transition: &publicationTransition{before: s.current, after: s.current},
		full:       true,
	})
	s.mu.Unlock()
}

// NotifyType wakes only streams watching a dynamic resource type, such as SDS.
func (s *Store) NotifyType(typeURL string) {
	s.mu.Lock()
	s.notifyLocked(Update{
		version:    s.current.Version(),
		transition: &publicationTransition{before: s.current, after: s.current},
		full:       true,
		fullTypes:  sets.New(typeURL),
	})
	s.mu.Unlock()
}

func (s *Store) notifyLocked(update Update) {
	if !update.full {
		types := make([]string, 0, len(update.affectedTypes))
		for typeURL := range update.affectedTypes {
			types = append(types, typeURL)
		}
		sort.Strings(types)
		log.Info("XDS: Incremental Pushing", "connected_endpoints", len(s.subscribers),
			"version", update.version, "types", types)
	}
	for _, subscriber := range s.affectedSubscribersLocked(update) {
		// Capacity-one, type-aware mailbox; the first coalescing boundary.
		// PushScheduler merges later duplicates.
		select {
		case subscriber.updates <- update:
		default:
			merged := update
			select {
			case pending := <-subscriber.updates:
				merged = Merge(pending, update)
			default:
			}
			select {
			case subscriber.updates <- merged:
			default:
			}
		}
	}
}
