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

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// AuthorizationGenerator projects global, namespace, and workload-selector
// authorizations from the authenticated client's scoped workloads.
type AuthorizationGenerator struct{}

func (AuthorizationGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.WorkloadAuthorizationType {
		return GeneratedDelta{}, fmt.Errorf("authorization generator does not support type URL %q", request.TypeURL)
	}
	if !request.Full && !request.Update.FullFor(model.WorkloadAuthorizationType) {
		return generateAuthorizationIncremental(request), nil
	}
	selected := make(map[string]model.Resource)
	for _, resource := range selectAuthorizationResources(request.Scope, request.Snapshot, selectionNames(request.Subscription)) {
		selected[resource.XDSName] = resource
	}
	return diffSelected(request.Subscription, selected), nil
}

func selectAuthorizationResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	names []string,
) []model.Resource {
	visibility := newAuthorizationVisibility(scope, snapshot)
	if !visibility.hasWorkloads {
		return nil
	}
	selected := snapshot.ListGlobalAuthorizations()
	for namespace := range visibility.namespaces {
		selected = append(selected, snapshot.ListNamespaceAuthorizations(namespace)...)
	}
	for policyName := range visibility.policyNames {
		selected = append(selected, snapshot.Lookup(model.WorkloadAuthorizationType, policyName)...)
	}
	selected = orderedUnique(selected)
	if names == nil {
		return selected
	}
	allowed := resourceKeySet(selected)
	result := make([]model.Resource, 0, len(names))
	for _, name := range names {
		for _, resource := range snapshot.Lookup(model.WorkloadAuthorizationType, name) {
			if allowed.Contains(resource.Key) {
				result = append(result, resource)
			}
		}
	}
	return orderedUnique(result)
}

// Gateways serve ordinary endpoints cluster-wide; other clients use their
// authenticated endpoint/node scope. Sandbox-managed endpoints never contribute.
func authorizationWorkloadQuery(scope model.ClientScope) (model.WorkloadQuery, bool) {
	query := model.WorkloadQuery{WorkloadPoliciesOnly: true}
	if scope.Class == model.ClientEgressGateway {
		return query, true
	}
	query, ok := workloadScopeQuery(scope)
	query.WorkloadPoliciesOnly = true
	return query, ok
}

func workloadAuthorizationNames(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, name := range resource.Facts.Workload.AuthorizationRefs {
			result.Insert(name)
		}
	}
	return result
}

func workloadNamespaces(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil || resource.Facts.Workload.Principal.Kind != model.PrincipalServiceAccount {
			continue
		}
		result.Insert(resource.Facts.Workload.Principal.ServiceAccount.Namespace)
	}
	return result
}

func generateAuthorizationIncremental(request GenerationRequest) GeneratedDelta {
	authorizationChanges := request.Update.ReadOnlyChangesForType(model.WorkloadAuthorizationType)
	scopeChanged := scopedWorkloadChanged(request.Scope, request.Update)
	if !scopeChanged && len(authorizationChanges) == 0 {
		return GeneratedDelta{}
	}
	if !scopeChanged {
		// These changes already contain the exact old/new resources and are unique
		// by key. Diff them directly rather than allocating a candidate set and
		// looking the same resources up again in both publications.
		visible := func(snapshot model.ResourceSet, resource *model.Resource) bool {
			return resource != nil && request.Subscription.allows(*resource) &&
				authorizationVisibleForScope(request.Scope, snapshot, *resource)
		}
		var selected map[string]model.Resource
		var removed sets.Set[string]
		before, after := request.Update.Before(), request.Update.After()
		for _, change := range authorizationChanges {
			addResourceTransition(&selected, &removed, change.Old, change.New,
				visible(before, change.Old), visible(after, change.New))
		}
		return newSortedDelta(selected, removed, false)
	}
	after := newAuthorizationVisibility(request.Scope, request.Update.After())
	before := newAuthorizationVisibility(request.Scope, request.Update.Before())
	candidates := authorizationCandidates(before, after, authorizationChanges)
	visible := func(visibility authorizationVisibility) func(model.Resource) bool {
		return func(resource model.Resource) bool {
			return visibility.visible(resource) && request.Subscription.allows(resource)
		}
	}
	selected, removed := diffCandidateTransition(candidates,
		before.resources.Get, after.resources.Get, visible(before), visible(after))
	return newSortedDelta(selected, removed, false)
}

func authorizationCandidates(
	before, after authorizationVisibility,
	changes []model.ResourceChange,
) sets.Set[model.ResourceKey] {
	candidates := sets.NewWithLength[model.ResourceKey](len(changes))
	for _, change := range changes {
		candidates.Insert(change.Key)
	}
	if before.hasWorkloads != after.hasWorkloads {
		for _, snapshot := range []model.ResourceSet{before.resources, after.resources} {
			for _, resource := range snapshot.ListGlobalAuthorizations() {
				candidates.Insert(resource.Key)
			}
		}
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
