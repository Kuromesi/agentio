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
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// GenerationRequest is the immutable input to one resource generation pass.
// Full selects a complete snapshot diff; otherwise Update carries the indexed
// changes for the requested type.
type GenerationRequest struct {
	// Scope is the authenticated client visibility used to filter every
	// candidate resource; generators must never widen beyond it.
	Scope model.ClientScope
	// TypeURL is the single xDS type produced by this generation pass.
	TypeURL string
	// Subscription is the immutable view of this connection's cumulative
	// subscription state: wildcard flag, subscribed names, and sent versions.
	Subscription SubscriptionView
	// Snapshot is the publication view resources are generated from; its
	// version becomes the response system version.
	Snapshot model.ResourceSet
	// Update carries the indexed key-level changes and the before/after
	// publication transition consumed by the incremental path. It is unset when Full
	// is true.
	Update xdsstore.Update
	// Full selects the complete snapshot diff path instead of incremental generation.
	// It is set for initial reads, new subscriptions, and full-rebuild updates.
	Full bool
	// SubscribedNames is the immutable set of names explicitly subscribed by
	// this Delta request. Server-driven refreshes and unsubscribe-only requests
	// leave it empty.
	SubscribedNames []string
}

type generatedDenial struct {
	name string
	err  error
}

// GeneratedDelta describes deterministic sent-state changes. Resources become
// the successfully sent versions and Removed names are deleted, but only after
// the Delta stream accepts the response.
type GeneratedDelta struct {
	Resources []model.Resource
	Removed   []string

	denied         []generatedDenial
	allowed        []string
	elideSentState bool
}

// ResourceGenerator builds resources for one Delta xDS type without mutating
// stream state or writing to the stream.
type ResourceGenerator interface {
	Generate(context.Context, GenerationRequest) (GeneratedDelta, error)
}

func selectionNames(subscription SubscriptionView) []string {
	if subscription.Wildcard() {
		return nil
	}
	return subscription.Names()
}

func diffSelected(subscription SubscriptionView, selected map[string]model.Resource) GeneratedDelta {
	return diffResourceSelection(selected, subscription.SentNames(), subscription.SentVersion)
}

func diffResourceSelection(
	selected map[string]model.Resource,
	sentNames []string,
	sentVersion func(string) (string, bool),
) GeneratedDelta {
	resources := make([]model.Resource, 0, len(selected))
	for name, resource := range selected {
		if version, found := sentVersion(name); found && version == resource.Hash {
			continue
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	removed := make([]string, 0)
	for _, name := range sentNames {
		if _, found := selected[name]; !found {
			removed = append(removed, name)
		}
	}
	return GeneratedDelta{Resources: resources, Removed: removed}
}

// diffCandidateTransition diffs each candidate's visibility and content between
// the two publications, mapping renames to removals of the old wire name.
func diffCandidateTransition(
	candidates sets.Set[model.ResourceKey],
	lookupOld, lookupNew func(model.ResourceKey) (model.Resource, bool),
	oldVisible, newVisible func(model.Resource) bool,
) (map[string]model.Resource, sets.Set[string]) {
	var selected map[string]model.Resource
	var removed sets.Set[string]
	for key := range candidates {
		oldResource, hadOld := lookupOld(key)
		newResource, hasNew := lookupNew(key)
		var oldPointer, newPointer *model.Resource
		if hadOld {
			oldPointer = &oldResource
		}
		if hasNew {
			newPointer = &newResource
		}
		addResourceTransition(&selected, &removed, oldPointer, newPointer,
			hadOld && oldVisible(oldResource), hasNew && newVisible(newResource))
	}
	return selected, removed
}

func addResourceTransition(
	selected *map[string]model.Resource,
	removed *sets.Set[string],
	oldResource, newResource *model.Resource,
	oldVisible, newVisible bool,
) {
	if newVisible && (!oldVisible || oldResource.Hash != newResource.Hash) {
		if *selected == nil {
			*selected = make(map[string]model.Resource)
		}
		(*selected)[newResource.XDSName] = *newResource
	}
	if oldVisible && (!newVisible || oldResource.XDSName != newResource.XDSName) {
		if *removed == nil {
			*removed = sets.New[string]()
		}
		(*removed).Insert(oldResource.XDSName)
	}
}

// newSortedDelta builds the deterministic delta; a name that is re-selected
// drops out of the removal set.
func newSortedDelta(selected map[string]model.Resource, removedSet sets.Set[string], elideSentState bool) GeneratedDelta {
	resources := make([]model.Resource, 0, len(selected))
	for name, resource := range selected {
		removedSet.Delete(name)
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	removed := make([]string, 0, len(removedSet))
	for name := range removedSet {
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return GeneratedDelta{Resources: resources, Removed: removed, elideSentState: elideSentState}
}
