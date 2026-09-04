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

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
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
		return generateAuthorizationDirty(request), nil
	}
	selected := make(map[string]model.Resource)
	for _, resource := range selectAuthorizationResources(
		request.Scope, request.Snapshot, selectionNames(request.Subscription),
	) {
		selected[resource.XDSName] = resource
	}
	return diffSelected(request.Subscription, selected), nil
}

func selectAuthorizationResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	names []string,
) []model.Resource {
	if scope.Class == model.ClientEgressGateway {
		if names == nil {
			return snapshot.List(model.WorkloadAuthorizationType)
		}
		selected := make([]model.Resource, 0, len(names))
		for _, name := range names {
			for _, resource := range snapshot.Lookup(model.WorkloadAuthorizationType, name) {
				if scopeAllows(scope, resource) {
					selected = append(selected, resource)
				}
			}
		}
		return orderedUnique(selected)
	}

	selected := snapshot.ListGlobalAuthorizations()
	workloads := scopedWorkloads(scope, snapshot, model.AddressType)
	namespaces := workloadNamespaces(workloads)
	if namespace, found := scopeNamespace(scope); found {
		namespaces.Insert(namespace)
	}
	for namespace := range namespaces {
		selected = append(selected, snapshot.ListNamespaceAuthorizations(namespace)...)
	}
	for policyName := range workloadAuthorizationNames(workloads) {
		if resource, found := snapshot.Get(model.ResourceKey{
			TypeURL: model.WorkloadAuthorizationType,
			Name:    policyName,
		}); found {
			selected = append(selected, resource)
		}
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
