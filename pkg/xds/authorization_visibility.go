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
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// authorizationVisibility binds one client scope to one immutable publication and
// caches the namespace and exact-reference visibility derived from the scoped
// workloads.
type authorizationVisibility struct {
	resources    model.ResourceSet
	hasWorkloads bool
	namespaces   sets.Set[string]
	policyNames  sets.Set[string]
}

func newAuthorizationVisibility(scope model.ClientScope, resources model.ResourceSet) authorizationVisibility {
	visibility := authorizationVisibility{resources: resources}
	query, ok := authorizationWorkloadQuery(scope)
	if !ok {
		return visibility
	}
	workloads := resources.ListWorkloads(model.AddressType, query)
	visibility.hasWorkloads = len(workloads) > 0
	visibility.namespaces = workloadNamespaces(workloads)
	visibility.policyNames = workloadAuthorizationNames(workloads)
	return visibility
}

func (v authorizationVisibility) visible(resource model.Resource) bool {
	if !v.hasWorkloads {
		return false
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

func authorizationVisibleForScope(
	scope model.ClientScope,
	resources model.ResourceSet,
	resource model.Resource,
) bool {
	authorization := resource.Facts.Authorization
	if authorization == nil {
		return false
	}
	scopeQuery, found := authorizationWorkloadQuery(scope)
	if !found {
		return false
	}
	if authorization.Scope == model.AuthorizationScopeGlobal {
		return resources.HasWorkload(model.AddressType, scopeQuery)
	}
	if authorization.Scope == model.AuthorizationScopeNamespace {
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
