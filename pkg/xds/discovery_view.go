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
	"sort"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

// discoveryView binds one client scope to one immutable publication. Views are
// created per generation pass and used from a single goroutine.
type discoveryView struct {
	resources model.ResourceSet
	scope     model.ClientScope
	typeURL   string
}

func newDiscoveryView(scope model.ClientScope, resources model.ResourceSet, typeURL string) discoveryView {
	return discoveryView{resources: resources, scope: scope, typeURL: typeURL}
}

func (v discoveryView) hasScopedWorkload(query model.WorkloadQuery) bool {
	scopeQuery, found := workloadScopeQuery(v.scope)
	if !found {
		return false
	}
	query.SandboxUID = scopeQuery.SandboxUID
	query.NodeName = scopeQuery.NodeName
	return v.resources.HasWorkload(v.typeURL, query)
}

func (v discoveryView) visible(resource model.Resource) bool {
	if v.scope.Class == model.ClientEgressGateway {
		return true
	}
	if resource.Facts.GatewayOwner != "" && v.hasScopedWorkload(model.WorkloadQuery{
		GatewayReference: resource.Facts.GatewayOwner,
	}) {
		return true
	}
	if resource.IsWorkloadAddress() {
		return workloadMatchesScope(v.scope, resource)
	}
	if v.typeURL != model.AddressType {
		return false
	}
	return resource.Facts.Service != nil && v.hasScopedWorkload(model.WorkloadQuery{
		ServiceKey: resource.Facts.Service.ServiceKey,
	})
}

func (v discoveryView) ownedByGateway(gatewayKey string) []model.Resource {
	return v.resources.ListResourcesOwnedByGateway(v.typeURL, gatewayKey)
}

// authorizationView binds one client scope to one immutable publication and
// caches the namespace and exact-reference visibility derived from the scoped
// workloads.
type authorizationView struct {
	resources   model.ResourceSet
	all         bool
	namespaces  sets.Set[string]
	policyNames sets.Set[string]
}

func newAuthorizationView(scope model.ClientScope, resources model.ResourceSet) authorizationView {
	view := authorizationView{
		resources: resources,
		all:       scope.Class == model.ClientEgressGateway,
	}
	if view.all {
		return view
	}
	workloads := scopedWorkloads(scope, resources, model.AddressType)
	view.namespaces = workloadNamespaces(workloads)
	if namespace, found := scopeNamespace(scope); found {
		view.namespaces.Insert(namespace)
	}
	view.policyNames = workloadAuthorizationNames(workloads)
	return view
}

func (v authorizationView) visible(resource model.Resource) bool {
	if v.all {
		return true
	}
	authorization := resource.Facts.Authorization
	if authorization == nil {
		return false
	}
	if authorization.Scope == model.AuthorizationScopeGlobal {
		return true
	}
	if authorization.Scope == model.AuthorizationScopeNamespace {
		return v.namespaces.Contains(authorization.Namespace)
	}
	if v.policyNames.Contains(resource.Key.Name) {
		return true
	}
	return v.policyNames.Contains(resource.XDSName)
}

func generateAuthorizationDirty(request GenerationRequest) GeneratedDelta {
	authorizationChanges := request.Update.changesForType(model.WorkloadAuthorizationType)
	scopeChanged := scopedWorkloadChanged(request.Scope, request.Update)
	if !scopeChanged && len(authorizationChanges) == 0 {
		return GeneratedDelta{}
	}
	if !scopeChanged {
		candidates := sets.NewWithLength[model.ResourceKey](len(authorizationChanges))
		for _, change := range authorizationChanges {
			candidates.Insert(change.Key)
		}
		visible := func(snapshot model.ResourceSet) func(model.Resource) bool {
			return func(resource model.Resource) bool {
				return authorizationVisibleForScope(request.Scope, snapshot, resource) &&
					request.Subscription.allows(resource)
			}
		}
		selected, removed := diffCandidateTransition(candidates,
			request.Update.Before().Get, request.Update.After().Get,
			visible(request.Update.Before()), visible(request.Update.After()))
		return newSortedDelta(selected, removed, false)
	}
	after := newAuthorizationView(request.Scope, request.Update.After())
	before := newAuthorizationView(request.Scope, request.Update.Before())
	candidates := authorizationCandidates(before, after, authorizationChanges)
	visible := func(view authorizationView) func(model.Resource) bool {
		return func(resource model.Resource) bool {
			return view.visible(resource) && request.Subscription.allows(resource)
		}
	}
	selected, removed := diffCandidateTransition(candidates,
		before.resources.Get, after.resources.Get, visible(before), visible(after))
	return newSortedDelta(selected, removed, false)
}

func authorizationVisibleForScope(
	scope model.ClientScope,
	resources model.ResourceSet,
	resource model.Resource,
) bool {
	if scope.Class == model.ClientEgressGateway {
		return true
	}
	authorization := resource.Facts.Authorization
	if authorization == nil {
		return false
	}
	if authorization.Scope == model.AuthorizationScopeGlobal {
		return true
	}
	scopeQuery, found := workloadScopeQuery(scope)
	if !found {
		return false
	}
	if authorization.Scope == model.AuthorizationScopeNamespace {
		if namespace, direct := scopeNamespace(scope); direct && namespace == authorization.Namespace {
			return true
		}
		scopeQuery.Namespace = authorization.Namespace
		return resources.HasWorkload(model.AddressType, scopeQuery)
	}
	for _, name := range []string{resource.Key.Name, resource.XDSName} {
		if name == "" {
			continue
		}
		query := scopeQuery
		query.AuthorizationReference = name
		if resources.HasWorkload(model.AddressType, query) {
			return true
		}
	}
	return false
}

// scopedWorkloadChanged reports whether any Address change touches a workload
// in this scope. When none does, the scope's derived visibility is unchanged
// and dirty generation only needs to diff the changed policies themselves.
func scopedWorkloadChanged(scope model.ClientScope, update Update) bool {
	_, found := workloadScopeQuery(scope)
	if !found {
		return false
	}
	for _, change := range update.changesForType(model.AddressType) {
		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource != nil && workloadMatchesScope(scope, *resource) {
				return true
			}
		}
	}
	return false
}

func authorizationCandidates(
	before, after authorizationView,
	changes []model.ResourceChange,
) sets.Set[model.ResourceKey] {
	candidates := sets.NewWithLength[model.ResourceKey](len(changes))
	for _, change := range changes {
		candidates.Insert(change.Key)
	}
	namespaces := sets.NewWithLength[string](len(before.namespaces) + len(after.namespaces))
	namespaces.Merge(before.namespaces)
	namespaces.Merge(after.namespaces)
	for namespace := range namespaces {
		wasVisible := before.namespaces.Contains(namespace)
		isVisible := after.namespaces.Contains(namespace)
		if wasVisible == isVisible {
			continue
		}
		for _, resource := range before.resources.ListNamespaceAuthorizations(namespace) {
			candidates.Insert(resource.Key)
		}
		for _, resource := range after.resources.ListNamespaceAuthorizations(namespace) {
			candidates.Insert(resource.Key)
		}
	}
	policyNames := sets.NewWithLength[string](len(before.policyNames) + len(after.policyNames))
	policyNames.Merge(before.policyNames)
	policyNames.Merge(after.policyNames)
	for name := range policyNames {
		wasVisible := before.policyNames.Contains(name)
		isVisible := after.policyNames.Contains(name)
		if wasVisible == isVisible {
			continue
		}
		key := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}
		if _, found := before.resources.Get(key); found {
			candidates.Insert(key)
		}
		if _, found := after.resources.Get(key); found {
			candidates.Insert(key)
		}
	}
	return candidates
}

// generateWDSDirty diffs the update's before/after publications for this
// scope, without per-connection sent state.
func generateWDSDirty(request GenerationRequest, workloadsOnly bool) GeneratedDelta {
	if !request.Subscription.Wildcard() {
		names := selectionNames(request.Subscription)
		return diffWDSSelections(
			selectWorkloadResources(request.Scope, request.Update.Before(), request.TypeURL, names),
			selectWorkloadResources(request.Scope, request.Update.After(), request.TypeURL, names),
			workloadsOnly)
	}
	before := newDiscoveryView(request.Scope, request.Update.Before(), request.TypeURL)
	after := newDiscoveryView(request.Scope, request.Update.After(), request.TypeURL)
	changes := request.Update.changesForType(request.TypeURL)
	if stableWDSFacts(changes) {
		return diffWDSChanges(before, after, changes, workloadsOnly)
	}
	candidates := dirtyWDSCandidates(before, after, changes)
	return diffWDSCandidates(before, after, candidates, workloadsOnly)
}

func stableWDSFacts(changes []model.ResourceChange) bool {
	for _, change := range changes {
		if change.Old == nil || change.New == nil ||
			!change.Old.Facts.Equal(change.New.Facts) {
			return false
		}
	}
	return true
}

func serviceResourcesForKey(snapshot model.ResourceSet, serviceKey string) []model.Resource {
	result := make([]model.Resource, 0, 1)
	for _, resource := range snapshot.Lookup(model.AddressType, serviceKey) {
		if resource.Facts.Service != nil && resource.Facts.Service.ServiceKey == serviceKey {
			result = append(result, resource)
		}
	}
	return result
}

func dirtyWDSCandidates(before, after discoveryView, changes []model.ResourceChange) sets.Set[model.ResourceKey] {
	candidates := sets.NewWithLength[model.ResourceKey](len(changes))
	add := func(resource *model.Resource) {
		if resource != nil && resource.Key.TypeURL == before.typeURL {
			candidates.Insert(resource.Key)
		}
	}
	addResources := func(resources []model.Resource) {
		for index := range resources {
			add(&resources[index])
		}
	}
	for _, change := range changes {
		add(change.Old)
		add(change.New)
		if change.Old != nil && change.New != nil &&
			change.Old.Facts.Equal(change.New.Facts) {
			// A payload-only change cannot flip Service or Gateway visibility.
			continue
		}
		for _, workload := range []*model.Resource{change.Old, change.New} {
			if workload == nil || !workload.IsWorkloadAddress() ||
				!workloadMatchesScope(before.scope, *workload) {
				continue
			}
			if before.typeURL == model.AddressType {
				for _, serviceKey := range workload.Facts.Workload.ServiceKeys {
					addResources(serviceResourcesForKey(before.resources, serviceKey))
					addResources(serviceResourcesForKey(after.resources, serviceKey))
				}
			}
			for _, gatewayKey := range workload.Facts.Workload.GatewayReferences {
				addResources(before.ownedByGateway(gatewayKey))
				addResources(after.ownedByGateway(gatewayKey))
			}
		}
	}
	return candidates
}

func diffWDSCandidates(
	before, after discoveryView,
	candidates sets.Set[model.ResourceKey],
	workloadsOnly bool,
) GeneratedDelta {
	visible := func(view discoveryView) func(model.Resource) bool {
		return func(resource model.Resource) bool {
			if workloadsOnly && !resource.IsWorkloadAddress() {
				return false
			}
			return view.visible(resource)
		}
	}
	selected, removed := diffCandidateTransition(candidates,
		before.resources.Get, after.resources.Get, visible(before), visible(after))
	return newSortedDelta(selected, removed, true)
}

func diffWDSChanges(
	before, after discoveryView,
	changes []model.ResourceChange,
	workloadsOnly bool,
) GeneratedDelta {
	visible := func(view discoveryView, resource *model.Resource) bool {
		return resource != nil && (!workloadsOnly || resource.IsWorkloadAddress()) && view.visible(*resource)
	}
	var selected map[string]model.Resource
	var removed sets.Set[string]
	for _, change := range changes {
		addResourceTransition(&selected, &removed, change.Old, change.New,
			visible(before, change.Old), visible(after, change.New))
	}
	return newSortedDelta(selected, removed, true)
}

func diffWDSSelections(before, after []model.Resource, workloadsOnly bool) GeneratedDelta {
	byKey := func(resources []model.Resource) map[model.ResourceKey]model.Resource {
		result := make(map[model.ResourceKey]model.Resource, len(resources))
		for _, resource := range resources {
			if !workloadsOnly || resource.IsWorkloadAddress() {
				result[resource.Key] = resource
			}
		}
		return result
	}
	oldByKey := byKey(before)
	newByKey := byKey(after)
	candidates := sets.NewWithLength[model.ResourceKey](len(oldByKey) + len(newByKey))
	for key := range oldByKey {
		candidates.Insert(key)
	}
	for key := range newByKey {
		candidates.Insert(key)
	}
	lookup := func(resources map[model.ResourceKey]model.Resource) func(model.ResourceKey) (model.Resource, bool) {
		return func(key model.ResourceKey) (model.Resource, bool) {
			resource, found := resources[key]
			return resource, found
		}
	}
	always := func(model.Resource) bool { return true }
	selected, removed := diffCandidateTransition(candidates,
		lookup(oldByKey), lookup(newByKey), always, always)
	return newSortedDelta(selected, removed, false)
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
