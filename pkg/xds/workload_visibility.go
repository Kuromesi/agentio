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
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// workloadVisibility evaluates Workload and Address visibility for one client
// against an immutable resource snapshot. It is local to one generation pass.
type workloadVisibility struct {
	resources model.ResourceSet
	scope     model.ClientScope
	typeURL   string
}

func newWorkloadVisibility(scope model.ClientScope, resources model.ResourceSet, typeURL string) workloadVisibility {
	return workloadVisibility{resources: resources, scope: scope, typeURL: typeURL}
}

func (v workloadVisibility) hasScopedWorkload(query model.WorkloadQuery) bool {
	scopeQuery, found := workloadScopeQuery(v.scope)
	if !found {
		return false
	}
	query.WorkloadUID = scopeQuery.WorkloadUID
	query.SourceUID = scopeQuery.SourceUID
	query.Principal = scopeQuery.Principal
	query.NodeName = scopeQuery.NodeName
	return v.resources.HasWorkload(v.typeURL, query)
}

func (v workloadVisibility) visible(resource model.Resource) bool {
	if v.scope.Class == model.ClientEgressGateway {
		return true
	}
	if resource.Facts.GatewayOwner != "" && v.hasScopedWorkload(model.WorkloadQuery{
		GatewayReference: resource.Facts.GatewayOwner,
	}) {
		return true
	}
	if resource.Facts.GatewayOwner != "" {
		for _, sandbox := range v.resources.ListSandboxesReferencingGateway(resource.Facts.GatewayOwner) {
			if sandboxResourceVisible(v.scope, v.resources, sandbox) {
				return true
			}
		}
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

func (v workloadVisibility) ownedByGateway(gatewayKey string) []model.Resource {
	return v.resources.ListResourcesOwnedByGateway(v.typeURL, gatewayKey)
}

// scopedWorkloadChanged reports whether any Address change touches a workload
// in this scope. When none does, the scope's derived visibility is unchanged
// and incremental generation only needs to diff the changed policies themselves.
func scopedWorkloadChanged(scope model.ClientScope, update xdsstore.Update) bool {
	_, found := workloadScopeQuery(scope)
	if !found && scope.Class != model.ClientEgressGateway {
		return false
	}
	for _, change := range update.ReadOnlyChangesForType(model.AddressType) {
		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource != nil && resource.Facts.Workload != nil &&
				(scope.Class == model.ClientEgressGateway || workloadMatchesScope(scope, *resource)) {
				return true
			}
		}
	}
	return false
}
