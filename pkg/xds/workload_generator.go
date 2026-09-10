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

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// WorkloadGenerator serves networking state and independently matched Workload policies.
type WorkloadGenerator struct{}

func (g WorkloadGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.AddressType && request.TypeURL != model.WorkloadType {
		return GeneratedDelta{}, fmt.Errorf("workload generator does not support type URL %q", request.TypeURL)
	}
	if request.TypeURL == model.WorkloadType {
		return g.generateDirectWorkloads(request)
	}
	if request.Full {
		resources := selectWorkloadResources(
			request.Scope, request.Snapshot, request.TypeURL, selectionNames(request.Subscription),
		)
		if request.Subscription.Wildcard() && len(request.Subscription.sent) == 0 &&
			(request.Scope.Class == model.ClientDedicatedZTunnel || request.Scope.Class == model.ClientSharedZTunnel) {
			return GeneratedDelta{
				Resources:      collapseSortedXDSNames(resources),
				elideSentState: true,
			}, nil
		}
		selected := make(map[string]model.Resource)
		for _, resource := range resources {
			selected[resource.XDSName] = resource
		}
		delta := diffSelected(request.Subscription, selected)
		delta.elideSentState = request.Subscription.Wildcard()
		return delta, nil
	}
	return generateWDSIncremental(request, false), nil
}

// collapseSortedXDSNames preserves the full selection's deterministic
// last-key-wins behavior without rebuilding and sorting a second map.
func collapseSortedXDSNames(resources []model.Resource) []model.Resource {
	write := 0
	for read := range resources {
		if write > 0 && resources[write-1].XDSName == resources[read].XDSName {
			resources[write-1] = resources[read]
			continue
		}
		resources[write] = resources[read]
		write++
	}
	clear(resources[write:])
	return resources[:write]
}

func (g WorkloadGenerator) generateDirectWorkloads(request GenerationRequest) (GeneratedDelta, error) {
	sourceRequest := request
	sourceRequest.TypeURL = model.AddressType
	// Direct Workloads keep per-connection sent state even for wildcard
	// watches: only egress gateways consume them, and sent versions are what
	// let a full regeneration send a diff instead of retransmitting the entire set.
	projectDelta := func(delta GeneratedDelta) (GeneratedDelta, error) {
		projected, err := g.projectAddresses(delta.Resources)
		if err != nil {
			return GeneratedDelta{}, err
		}
		delta.Resources = projected
		delta.elideSentState = false
		return delta, nil
	}
	if request.Full || request.Update.FullFor(model.WorkloadType) {
		selected := make(map[string]model.Resource)
		addresses := selectWorkloadResources(
			request.Scope, request.Snapshot, model.AddressType, selectionNames(request.Subscription))
		projected, err := g.projectAddresses(addresses)
		if err != nil {
			return GeneratedDelta{}, err
		}
		for _, resource := range projected {
			selected[resource.XDSName] = resource
		}
		return diffSelected(request.Subscription, selected), nil
	}
	return projectDelta(generateWDSIncremental(sourceRequest, true))
}

func (g WorkloadGenerator) projectAddresses(addresses []model.Resource) ([]model.Resource, error) {
	result := make([]model.Resource, 0, len(addresses))
	for _, addressResource := range addresses {
		address := &workloadv1.Address{}
		if err := addressResource.Value.UnmarshalTo(address); err != nil {
			return nil, fmt.Errorf("decode Address %s: %w", addressResource.Key.Name, err)
		}
		workload := address.GetWorkload()
		if workload == nil {
			continue
		}
		// Deterministic marshaling keeps the projected hash stable across
		// regenerations; the default marshal randomizes map-field order and
		// would resend every workload on each full diff.
		value := new(anypb.Any)
		if err := anypb.MarshalFrom(value, workload, proto.MarshalOptions{Deterministic: true}); err != nil {
			return nil, fmt.Errorf("marshal direct Workload %s: %w", addressResource.Key.Name, err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.WorkloadType, Name: addressResource.Key.Name},
			addressResource.XDSName, value, addressResource.Aliases, addressResource.Facts)
		if err != nil {
			return nil, err
		}
		result = append(result, resource)
	}
	return result, nil
}

func selectWorkloadResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	typeURL string,
	names []string,
) []model.Resource {
	if scope.Class == model.ClientEgressGateway {
		if names == nil {
			return snapshot.List(typeURL)
		}
		selected := make([]model.Resource, 0, len(names))
		for _, name := range names {
			for _, resource := range snapshot.Lookup(typeURL, name) {
				if typeURL == model.AddressType || resource.IsWorkloadAddress() {
					selected = append(selected, resource)
				}
			}
		}
		for serviceKey := range serviceKeysForNames(snapshot, names) {
			for _, resource := range snapshot.ListServiceMembers(typeURL, serviceKey) {
				if resource.IsWorkloadAddress() {
					selected = append(selected, resource)
				}
			}
		}
		return orderedUnique(selected)
	}

	workloads := scopedWorkloads(scope, snapshot, typeURL)
	referencedGateways := gatewayReferenceKeys(workloads)
	referencedGateways.Merge(sandboxGatewayReferenceKeys(snapshot, workloads))
	withGateways := func(selected []model.Resource) []model.Resource {
		selected = append(selected, gatewayResourcesForKeys(snapshot, typeURL, referencedGateways)...)
		return orderedUnique(selected)
	}
	allowedWorkloads := resourceKeySet(workloads)
	serviceKeys := workloadServiceKeys(workloads)
	if names == nil {
		// The workload slice is private to this selection, so related resources can reuse its backing array.
		selected := workloads
		if typeURL == model.AddressType {
			selected = append(selected, selectedServices(snapshot, serviceKeys)...)
		}
		return withGateways(selected)
	}
	if len(names) == 0 {
		if scope.Class == model.ClientSharedZTunnel {
			return withGateways(workloads)
		}
		return nil
	}

	selected := make([]model.Resource, 0, len(names))
	if scope.Class == model.ClientSharedZTunnel {
		// Node-local workloads stay implicit; explicit workload and Service/VIP
		// lookups are not node-filtered.
		selected = append(selected, workloads...)
		selectedServiceKeys := serviceKeysForNames(snapshot, names)
		for _, name := range names {
			for _, candidate := range snapshot.Lookup(typeURL, name) {
				if candidate.IsWorkloadAddress() {
					selected = append(selected, candidate)
					continue
				}
				if typeURL != model.AddressType {
					continue
				}
				if candidate.Facts.Service != nil {
					selected = append(selected, candidate)
					selectedServiceKeys.Insert(candidate.Facts.Service.ServiceKey)
				}
			}
		}
		for serviceKey := range selectedServiceKeys {
			for _, endpoint := range snapshot.ListServiceMembers(typeURL, serviceKey) {
				if endpoint.IsWorkloadAddress() {
					selected = append(selected, endpoint)
				}
			}
		}
		return withGateways(selected)
	}
	selectedServiceKeys := sets.New[string]()
	for _, name := range names {
		for _, candidate := range snapshot.Lookup(typeURL, name) {
			switch {
			case candidate.IsWorkloadAddress():
				if scope.Class != model.ClientSharedZTunnel {
					if allowedWorkloads.Contains(candidate.Key) {
						selected = append(selected, candidate)
					}
				}
			case typeURL == model.AddressType && candidate.Facts.Service != nil:
				serviceKey := candidate.Facts.Service.ServiceKey
				if serviceKeys.Contains(serviceKey) {
					selected = append(selected, candidate)
					selectedServiceKeys.Insert(serviceKey)
				}
			}
		}
	}
	for serviceKey := range serviceKeysForNames(snapshot, names) {
		if serviceKeys.Contains(serviceKey) {
			selectedServiceKeys.Insert(serviceKey)
		}
	}
	for serviceKey := range selectedServiceKeys {
		for _, endpoint := range snapshot.ListServiceMembers(typeURL, serviceKey) {
			if !endpoint.IsWorkloadAddress() {
				continue
			}
			if allowedWorkloads.Contains(endpoint.Key) {
				selected = append(selected, endpoint)
			}
		}
	}
	return withGateways(selected)
}

func serviceKeysForNames(snapshot model.ResourceSet, names []string) sets.Set[string] {
	serviceKeys := sets.New[string]()
	if names == nil {
		return serviceKeys
	}
	for _, name := range names {
		for _, resource := range snapshot.Lookup(model.AddressType, name) {
			if resource.Facts.Service != nil {
				serviceKeys.Insert(resource.Facts.Service.ServiceKey)
			}
		}
	}
	return serviceKeys
}

func workloadMatchesScope(scope model.ClientScope, resource model.Resource) bool {
	workload := resource.Facts.Workload
	if workload == nil {
		return false
	}
	switch scope.Class {
	case model.ClientDedicatedZTunnel:
		return scope.WorkloadUID != "" && scope.SourceUID != "" && workload.WorkloadUID == scope.WorkloadUID && workload.SourceUID == scope.SourceUID && workload.Principal == scope.Principal
	case model.ClientSharedZTunnel:
		return workload.NodeName == scope.NodeName
	default:
		return false
	}
}

func scopedWorkloads(scope model.ClientScope, snapshot model.ResourceSet, typeURL string) []model.Resource {
	query, found := workloadScopeQuery(scope)
	if !found {
		return nil
	}
	return snapshot.ListWorkloads(typeURL, query)
}

func workloadScopeQuery(scope model.ClientScope) (model.WorkloadQuery, bool) {
	switch scope.Class {
	case model.ClientDedicatedZTunnel:
		if scope.WorkloadUID != "" && scope.SourceUID != "" {
			return model.WorkloadQuery{WorkloadUID: scope.WorkloadUID, SourceUID: scope.SourceUID, Principal: &scope.Principal}, true
		}
		return model.WorkloadQuery{}, false
	case model.ClientSharedZTunnel:
		return model.WorkloadQuery{NodeName: scope.NodeName}, true
	default:
		return model.WorkloadQuery{}, false
	}
}

func selectedServices(snapshot model.ResourceSet, serviceKeys sets.Set[string]) []model.Resource {
	result := make([]model.Resource, 0, len(serviceKeys))
	for serviceKey := range serviceKeys {
		for _, resource := range snapshot.Lookup(model.AddressType, serviceKey) {
			if resource.Facts.Service != nil && resource.Facts.Service.ServiceKey == serviceKey {
				result = append(result, resource)
			}
		}
	}
	return result
}

func gatewayReferenceKeys(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, key := range resource.Facts.Workload.GatewayReferences {
			result.Insert(key)
		}
	}
	return result
}

func workloadServiceKeys(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, key := range resource.Facts.Workload.ServiceKeys {
			result.Insert(key)
		}
	}
	return result
}

func gatewayResourcesForKeys(
	snapshot model.ResourceSet,
	typeURL string,
	keys sets.Set[string],
) []model.Resource {
	result := make([]model.Resource, 0, len(keys))
	for key := range keys {
		result = append(result, snapshot.ListResourcesOwnedByGateway(typeURL, key)...)
	}
	return orderedUnique(result)
}

// generateWDSIncremental diffs the update's before/after publications for this
// scope, without per-connection sent state.
func generateWDSIncremental(request GenerationRequest, workloadsOnly bool) GeneratedDelta {
	if !request.Subscription.Wildcard() {
		names := selectionNames(request.Subscription)
		return diffWDSSelections(
			selectWorkloadResources(request.Scope, request.Update.Before(), request.TypeURL, names),
			selectWorkloadResources(request.Scope, request.Update.After(), request.TypeURL, names),
			workloadsOnly)
	}
	before := newWorkloadVisibility(request.Scope, request.Update.Before(), request.TypeURL)
	after := newWorkloadVisibility(request.Scope, request.Update.After(), request.TypeURL)
	changes := request.Update.ReadOnlyChangesForType(request.TypeURL)
	sandboxChanges := request.Update.ReadOnlyChangesForType(model.SandboxType)
	if stableWDSFacts(changes) && !request.Update.SandboxGatewayFactsChanged() {
		return diffWDSChanges(before, after, changes, workloadsOnly)
	}
	candidates := affectedWDSCandidates(before, after, changes)
	addSandboxGatewayCandidates(candidates, before, after, sandboxChanges)
	return diffWDSCandidates(before, after, candidates, workloadsOnly)
}

func addSandboxGatewayCandidates(candidates sets.Set[model.ResourceKey], before, after workloadVisibility, changes []model.ResourceChange) {
	for _, change := range changes {
		if change.Old != nil && change.New != nil && change.Old.Facts.Equal(change.New.Facts) {
			continue
		}
		for _, sandbox := range []*model.Resource{change.Old, change.New} {
			if sandbox == nil || sandbox.Facts.Sandbox == nil {
				continue
			}
			for _, key := range sandbox.Facts.Sandbox.GatewayReferences {
				for _, visibility := range []workloadVisibility{before, after} {
					for _, resource := range visibility.ownedByGateway(key) {
						candidates.Insert(resource.Key)
					}
				}
			}
		}
	}
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

func affectedWDSCandidates(before, after workloadVisibility, changes []model.ResourceChange) sets.Set[model.ResourceKey] {
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
			gateways := sets.New(workload.Facts.Workload.GatewayReferences...)
			gateways.Merge(sandboxGatewayReferenceKeys(before.resources, []model.Resource{*workload}))
			gateways.Merge(sandboxGatewayReferenceKeys(after.resources, []model.Resource{*workload}))
			for gatewayKey := range gateways {
				addResources(before.ownedByGateway(gatewayKey))
				addResources(after.ownedByGateway(gatewayKey))
			}
		}
	}
	return candidates
}

func diffWDSCandidates(
	before, after workloadVisibility,
	candidates sets.Set[model.ResourceKey],
	workloadsOnly bool,
) GeneratedDelta {
	visible := func(visibility workloadVisibility) func(model.Resource) bool {
		return func(resource model.Resource) bool {
			if workloadsOnly && !resource.IsWorkloadAddress() {
				return false
			}
			return visibility.visible(resource)
		}
	}
	selected, removed := diffCandidateTransition(candidates,
		before.resources.Get, after.resources.Get, visible(before), visible(after))
	return newSortedDelta(selected, removed, true)
}

func diffWDSChanges(
	before, after workloadVisibility,
	changes []model.ResourceChange,
	workloadsOnly bool,
) GeneratedDelta {
	visible := func(visibility workloadVisibility, resource *model.Resource) bool {
		return resource != nil && (!workloadsOnly || resource.IsWorkloadAddress()) && visibility.visible(*resource)
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
