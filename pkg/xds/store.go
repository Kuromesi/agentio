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
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

// Update describes one committed publication change delivered to subscribers.
type Update struct {
	version string
	// transition is shared by every affected connection so fanout copies only a
	// pointer rather than two ResourceSet values. Its publications are immutable.
	transition *publicationTransition
	// changes contains the net key-level delta since this subscriber last
	// consumed an update. Old/New resources are immutable and safe to share.
	changes map[model.ResourceKey]model.ResourceChange
	// changesByType is the shared generator index for changes. It prevents every
	// affected connection from filtering the complete dirty batch again.
	changesByType map[string][]model.ResourceChange
	// changesByName indexes changes by old and new wire names and aliases.
	changesByName map[string]map[string][]model.ResourceChange
	// dirtyTypes is the fixed-cardinality type index used for connection filtering.
	dirtyTypes sets.Set[string]
	// full asks generators to rebuild state. An empty fullTypes means every
	// watched type; otherwise only the listed dynamic types need a full read.
	full      bool
	fullTypes sets.Set[string]
}

type publicationTransition struct {
	before model.ResourceSet
	after  model.ResourceSet
}

// Version returns the version of the snapshot that produced this update.
func (u Update) Version() string { return u.version }

// Before returns the publication view immediately before this update.
func (u Update) Before() model.ResourceSet {
	if u.transition == nil {
		return model.ResourceSet{}
	}
	return u.transition.before
}

// After returns the publication view committed by this update.
func (u Update) After() model.ResourceSet {
	if u.transition == nil {
		return model.ResourceSet{}
	}
	return u.transition.after
}

// Affects reports whether a watched type needs work for this update.
func (u Update) Affects(typeURL string) bool {
	if u.FullFor(typeURL) {
		return true
	}
	return u.dirtyTypes.Contains(typeURL)
}

// FullFor reports whether typeURL must be regenerated from its complete source.
func (u Update) FullFor(typeURL string) bool {
	if !u.full {
		return false
	}
	if len(u.fullTypes) == 0 {
		return true
	}
	return u.fullTypes.Contains(typeURL)
}

// ChangesForType returns the dirty changes for typeURL in ResourceKey order.
// The returned slice does not share mutable storage with the update indexes.
func (u Update) ChangesForType(typeURL string) []model.ResourceChange {
	return append([]model.ResourceChange(nil), u.changesForType(typeURL)...)
}

// changesForType returns the immutable, pre-sorted publication index for use
// inside the push pipeline. Callers must not mutate the returned slice.
func (u Update) changesForType(typeURL string) []model.ResourceChange {
	return u.changesByType[typeURL]
}

// ChangesForNames returns the dirty changes for typeURL which match at least
// one requested name. Both the old and new wire names and aliases are indexed.
// A resource that matches multiple names is returned once.
func (u Update) ChangesForNames(typeURL string, names []string) []model.ResourceChange {
	byName := u.changesByName[typeURL]
	if len(byName) == 0 || len(names) == 0 {
		return nil
	}
	byKey := make(map[model.ResourceKey]model.ResourceChange)
	for _, name := range names {
		for _, change := range byName[name] {
			byKey[change.Key] = change
		}
	}
	changes := make([]model.ResourceChange, 0, len(byKey))
	for _, change := range byKey {
		changes = append(changes, change)
	}
	return orderedChanges(changes)
}

func orderedChanges(changes []model.ResourceChange) []model.ResourceChange {
	if len(changes) == 0 {
		return nil
	}
	result := append([]model.ResourceChange(nil), changes...)
	sortChanges(result)
	return result
}

func sortChanges(changes []model.ResourceChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Key.TypeURL != changes[j].Key.TypeURL {
			return changes[i].Key.TypeURL < changes[j].Key.TypeURL
		}
		return changes[i].Key.Name < changes[j].Key.Name
	})
}

type subscriber struct {
	updates chan Update
	types   sets.Set[string]
}

// Subscription allows an xDS stream to add watched types as requests arrive.
// Store notifications can then skip connections that cannot be affected.
type Subscription struct {
	store   *Store
	id      uint64
	updates <-chan Update
}

func (s *Subscription) Updates() <-chan Update { return s.updates }

func (s *Subscription) Watch(typeURL string) {
	s.store.mu.Lock()
	if sub := s.store.subscribers[s.id]; sub != nil {
		if !sub.types.Contains(typeURL) {
			sub.types.Insert(typeURL)
			byID := s.store.subscribersByType[typeURL]
			if byID == nil {
				byID = make(map[uint64]*subscriber)
				s.store.subscribersByType[typeURL] = byID
			}
			byID[s.id] = sub
		}
	}
	s.store.mu.Unlock()
}

type Store struct {
	mu          sync.RWMutex
	current     model.ResourceSet
	subscribers map[uint64]*subscriber
	// subscribersByType indexes subscribers by watched type; all-type
	// subscribers are indexed separately.
	subscribersByType map[string]map[uint64]*subscriber
	allSubscribers    map[uint64]*subscriber
	nextID            uint64
}

func NewStore(initial model.ResourceSet) *Store {
	return &Store{
		current:           initial,
		subscribers:       make(map[uint64]*subscriber),
		subscribersByType: make(map[string]map[uint64]*subscriber),
		allSubscribers:    make(map[uint64]*subscriber),
	}
}

func (s *Store) Snapshot() model.ResourceSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

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
		full:       true, fullTypes: sets.New(typeURL),
	})
	s.mu.Unlock()
}

func (s *Store) notifyLocked(update Update) {
	for _, subscriber := range s.affectedSubscribersLocked(update) {
		// Capacity-one, type-aware mailbox; the first coalescing boundary.
		// PushScheduler merges later duplicates.
		select {
		case subscriber.updates <- update:
		default:
			merged := update
			select {
			case pending := <-subscriber.updates:
				merged = mergeUpdates(pending, update)
			default:
			}
			select {
			case subscriber.updates <- merged:
			default:
			}
		}
	}
}

func (s *Store) Subscribe(ctx context.Context) ResourceSubscription {
	return s.subscribe(ctx, false)
}

func (s *Store) subscribeAll(ctx context.Context) <-chan Update {
	return s.subscribe(ctx, true).Updates()
}

func (s *Store) subscribe(ctx context.Context, all bool) *Subscription {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	updates := make(chan Update, 1)
	s.subscribers[id] = &subscriber{updates: updates, types: sets.New[string]()}
	if all {
		s.allSubscribers[id] = s.subscribers[id]
	}
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if subscriber := s.subscribers[id]; subscriber != nil {
			delete(s.allSubscribers, id)
			for typeURL := range subscriber.types {
				delete(s.subscribersByType[typeURL], id)
				if len(s.subscribersByType[typeURL]) == 0 {
					delete(s.subscribersByType, typeURL)
				}
			}
		}
		delete(s.subscribers, id)
		s.mu.Unlock()
	}()
	return &Subscription{store: s, id: id, updates: updates}
}

func updateFor(version string, changes []model.ResourceChange) Update {
	indexed := make(map[model.ResourceKey]model.ResourceChange, len(changes))
	types := sets.New[string]()
	byType := make(map[string][]model.ResourceChange)
	byName := make(map[string]map[string][]model.ResourceChange)
	for _, change := range changes {
		indexed[change.Key] = change
		types.Insert(change.Key.TypeURL)
		byType[change.Key.TypeURL] = append(byType[change.Key.TypeURL], change)
		indexChangeByName(byName, change)
		indexDerivedSelectionChanges(types, change)
	}
	for typeURL := range byType {
		sortChanges(byType[typeURL])
	}
	return Update{
		version:       version,
		changes:       indexed,
		changesByType: byType,
		changesByName: byName,
		dirtyTypes:    types,
	}
}

func updateBetween(before, after model.ResourceSet, changes []model.ResourceChange) Update {
	update := updateFor(after.Version(), changes)
	update.transition = &publicationTransition{before: before, after: after}
	return update
}

func coalesceChanges(changes []model.ResourceChange) []model.ResourceChange {
	indexed := make(map[model.ResourceKey]model.ResourceChange, len(changes))
	for _, change := range changes {
		if existing, found := indexed[change.Key]; found {
			change.Old = existing.Old
		}
		indexed[change.Key] = change
	}
	result := make([]model.ResourceChange, 0, len(indexed))
	for _, change := range indexed {
		if sameResource(change.Old, change.New) {
			continue
		}
		result = append(result, change)
	}
	return result
}

func (s *Store) affectedSubscribersLocked(update Update) map[uint64]*subscriber {
	if update.full && len(update.fullTypes) == 0 {
		return s.subscribers
	}
	result := make(map[uint64]*subscriber, len(s.allSubscribers))
	maps.Copy(result, s.allSubscribers)
	affectedTypes := sets.NewWithLength[string](len(update.fullTypes) + len(update.dirtyTypes))
	for typeURL := range update.fullTypes {
		affectedTypes.Insert(typeURL)
	}
	for typeURL := range update.dirtyTypes {
		affectedTypes.Insert(typeURL)
	}
	if update.dirtyTypes == nil {
		for key := range update.changes {
			affectedTypes.Insert(key.TypeURL)
		}
	}
	for typeURL := range affectedTypes {
		maps.Copy(result, s.subscribersByType[typeURL])
	}
	return result
}

func mergeUpdates(older, newer Update) Update {
	merged := Update{version: newer.version, full: older.full || newer.full}
	if older.transition != nil && newer.transition != nil {
		merged.transition = &publicationTransition{
			before: older.transition.before,
			after:  newer.transition.after,
		}
	}
	if merged.full {
		if older.full && len(older.fullTypes) == 0 || newer.full && len(newer.fullTypes) == 0 {
			merged.fullTypes = nil
		} else {
			merged.fullTypes = sets.NewWithLength[string](len(older.fullTypes) + len(newer.fullTypes))
			for typeURL := range older.fullTypes {
				merged.fullTypes.Insert(typeURL)
			}
			for typeURL := range newer.fullTypes {
				merged.fullTypes.Insert(typeURL)
			}
		}
	}
	merged.changes = make(map[model.ResourceKey]model.ResourceChange, len(older.changes)+len(newer.changes))
	merged.dirtyTypes = sets.NewWithLength[string](len(older.dirtyTypes) + len(newer.dirtyTypes))
	for typeURL := range older.dirtyTypes {
		merged.dirtyTypes.Insert(typeURL)
	}
	for typeURL := range newer.dirtyTypes {
		merged.dirtyTypes.Insert(typeURL)
	}
	maps.Copy(merged.changes, older.changes)
	for key, change := range newer.changes {
		if existing, found := merged.changes[key]; found {
			change.Old = existing.Old
		}
		if sameResource(change.Old, change.New) {
			delete(merged.changes, key)
		} else {
			merged.changes[key] = change
		}
	}
	// A type can disappear from the net delta when add/delete or update/revert
	// events merge while a connection is busy.
	clear(merged.dirtyTypes)
	merged.changesByType = make(map[string][]model.ResourceChange)
	merged.changesByName = make(map[string]map[string][]model.ResourceChange)
	for key := range merged.changes {
		merged.dirtyTypes.Insert(key.TypeURL)
		merged.changesByType[key.TypeURL] = append(merged.changesByType[key.TypeURL], merged.changes[key])
		indexChangeByName(merged.changesByName, merged.changes[key])
		indexDerivedSelectionChanges(merged.dirtyTypes, merged.changes[key])
	}
	for typeURL := range merged.changesByType {
		sortChanges(merged.changesByType[typeURL])
	}
	return merged
}

func indexChangeByName(index map[string]map[string][]model.ResourceChange, change model.ResourceChange) {
	byName := index[change.Key.TypeURL]
	if byName == nil {
		byName = make(map[string][]model.ResourceChange)
		index[change.Key.TypeURL] = byName
	}
	names := make([]string, 0, 4)
	addName := func(name string) {
		if name == "" {
			return
		}
		if slices.Contains(names, name) {
			return
		}
		names = append(names, name)
	}
	for _, resource := range []*model.Resource{change.Old, change.New} {
		if resource == nil {
			continue
		}
		addName(resource.Key.Name)
		addName(resource.XDSName)
		for _, alias := range resource.Aliases {
			addName(alias)
		}
	}
	for _, name := range names {
		byName[name] = append(byName[name], change)
	}
}

// indexDerivedSelectionChanges marks the Workload and WorkloadAuthorization
// watches dirty when their source Address changes.
func indexDerivedSelectionChanges(types sets.Set[string], change model.ResourceChange) {
	if change.Key.TypeURL != model.AddressType {
		return
	}
	for _, resource := range []*model.Resource{change.Old, change.New} {
		if resource == nil {
			continue
		}
		if resource.Facts.Workload != nil {
			types.Insert(model.WorkloadType)
			types.Insert(model.WorkloadAuthorizationType)
		}
		if resource.Facts.Service != nil {
			// Service changes must wake Workload watches: on-demand names
			// resolve through Address resources.
			types.Insert(model.WorkloadType)
		}
	}
}

func sameResource(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
