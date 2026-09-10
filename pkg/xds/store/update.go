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
	"slices"
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
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
	// affected connection from filtering the complete incremental batch again.
	changesByType map[string][]model.ResourceChange
	// changesByName indexes changes by old and new wire names and aliases.
	changesByName map[string]map[string][]model.ResourceChange
	// affectedTypes includes changed resource types and types affected through
	// dependencies, so connections watching either can be notified.
	affectedTypes sets.Set[string]
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
	return u.affectedTypes.Contains(typeURL)
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

// ChangesForType returns the changes for typeURL in ResourceKey order.
// The returned slice does not share mutable storage with the update indexes.
func (u Update) ChangesForType(typeURL string) []model.ResourceChange {
	return append([]model.ResourceChange(nil), u.ReadOnlyChangesForType(typeURL)...)
}

// ReadOnlyChangesForType borrows the immutable, pre-sorted publication index
// without copying. Callers must not modify the slice or its resources. Use
// ChangesForType when a mutable slice is needed.
func (u Update) ReadOnlyChangesForType(typeURL string) []model.ResourceChange {
	return u.changesByType[typeURL]
}

// ChangesForNames returns the changes for typeURL which match at least
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
		affectedTypes: types,
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

// Merge combines consecutive updates, retaining the first before snapshot and
// the latest after snapshot. Inputs and their resource indexes remain immutable.
func Merge(older, newer Update) Update {
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
	merged.affectedTypes = sets.NewWithLength[string](len(older.affectedTypes) + len(newer.affectedTypes))
	for typeURL := range older.affectedTypes {
		merged.affectedTypes.Insert(typeURL)
	}
	for typeURL := range newer.affectedTypes {
		merged.affectedTypes.Insert(typeURL)
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
	clear(merged.affectedTypes)
	merged.changesByType = make(map[string][]model.ResourceChange)
	merged.changesByName = make(map[string]map[string][]model.ResourceChange)
	for key := range merged.changes {
		merged.affectedTypes.Insert(key.TypeURL)
		merged.changesByType[key.TypeURL] = append(merged.changesByType[key.TypeURL], merged.changes[key])
		indexChangeByName(merged.changesByName, merged.changes[key])
		indexDerivedSelectionChanges(merged.affectedTypes, merged.changes[key])
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

func sameResource(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
