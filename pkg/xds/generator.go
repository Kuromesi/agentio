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
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

// SubscriptionView is an immutable copy of the subscription state visible to a
// resource generator. Its accessors never expose the Delta stream's live maps.
type SubscriptionView struct {
	wildcard bool
	names    []string
	sent     map[string]string
}

func newSubscriptionView(watch *watchState) SubscriptionView {
	names := sortedNames(watch.names)
	sent := make(map[string]string, len(watch.sent))
	maps.Copy(sent, watch.sent)
	return SubscriptionView{wildcard: watch.wildcard, names: names, sent: sent}
}

func newDirtySubscriptionView(watch *watchState, typeURL string, update Update) SubscriptionView {
	view := SubscriptionView{
		wildcard: watch.wildcard,
		names:    sortedNames(watch.names),
		sent:     make(map[string]string),
	}
	var changes []model.ResourceChange
	if view.wildcard {
		changes = update.changesForType(typeURL)
	} else {
		changes = update.ChangesForNames(typeURL, view.names)
	}
	copySentForChanges(&view, watch, changes)
	return view
}

func copySentForChanges(view *SubscriptionView, watch *watchState, changes []model.ResourceChange) {
	copySent := func(resource *model.Resource) {
		if resource == nil {
			return
		}
		if version, found := watch.sent[resource.XDSName]; found {
			view.sent[resource.XDSName] = version
		}
	}
	for _, change := range changes {
		copySent(change.Old)
		copySent(change.New)
	}
}

// Wildcard reports whether every resource of this type is subscribed.
func (s SubscriptionView) Wildcard() bool {
	return s.wildcard
}

// Names returns the explicitly subscribed names in lexical order.
func (s SubscriptionView) Names() []string {
	result := make([]string, len(s.names))
	copy(result, s.names)
	return result
}

// SentVersion returns the version last sent successfully for a wire name.
func (s SubscriptionView) SentVersion(name string) (string, bool) {
	version, found := s.sent[name]
	return version, found
}

// SentNames returns successfully sent wire names in lexical order.
func (s SubscriptionView) SentNames() []string {
	result := make([]string, 0, len(s.sent))
	for name := range s.sent {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (s SubscriptionView) allows(resource model.Resource) bool {
	if s.wildcard {
		return true
	}
	if containsSorted(s.names, resource.XDSName) {
		return true
	}
	for _, alias := range resource.Aliases {
		if containsSorted(s.names, alias) {
			return true
		}
	}
	return false
}

func containsSorted(values []string, value string) bool {
	_, found := slices.BinarySearch(values, value)
	return found
}

// GenerationRequest is the immutable input to one resource generation pass.
// Full selects a complete snapshot diff; otherwise Update carries the indexed
// dirty changes for the requested type.
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
	// publication transition consumed by the dirty path. It is unset when Full
	// is true.
	Update Update
	// Full selects the complete snapshot diff path instead of dirty generation.
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

// SnapshotGenerator generates precompiled resources from store snapshots and dirty updates.
type SnapshotGenerator struct{}

func (SnapshotGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL == "" {
		return GeneratedDelta{}, fmt.Errorf("generation type URL is required")
	}
	if request.Full {
		return generateSnapshotDiff(request), nil
	}
	return generateSnapshotDirty(request), nil
}

func generateSnapshotDiff(request GenerationRequest) GeneratedDelta {
	selected := make(map[string]model.Resource)
	for _, resource := range selectGeneric(
		request.Scope, request.Snapshot, request.TypeURL, selectionNames(request.Subscription),
	) {
		selected[resource.XDSName] = resource
	}
	return diffSelected(request.Subscription, selected)
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

func generateSnapshotDirty(request GenerationRequest) GeneratedDelta {
	var changes []model.ResourceChange
	if request.Subscription.Wildcard() {
		changes = request.Update.changesForType(request.TypeURL)
	} else {
		changes = request.Update.ChangesForNames(request.TypeURL, request.Subscription.Names())
	}

	selected := make(map[string]model.Resource, len(changes))
	removedSet := sets.New[string]()
	for _, change := range changes {
		oldSelected := change.Old != nil && scopeAllows(request.Scope, *change.Old) && request.Subscription.allows(*change.Old)
		newSelected := change.New != nil && scopeAllows(request.Scope, *change.New) && request.Subscription.allows(*change.New)
		if newSelected {
			selected[change.New.XDSName] = *change.New
		}
		if oldSelected && (!newSelected || change.Old.XDSName != change.New.XDSName) {
			if _, sent := request.Subscription.SentVersion(change.Old.XDSName); sent {
				removedSet.Insert(change.Old.XDSName)
			}
		}
	}

	resources := make([]model.Resource, 0, len(selected))
	for name, resource := range selected {
		removedSet.Delete(name)
		if version, found := request.Subscription.SentVersion(name); found && version == resource.Hash {
			continue
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	removed := make([]string, 0, len(removedSet))
	for name := range removedSet {
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return GeneratedDelta{Resources: resources, Removed: removed}
}
