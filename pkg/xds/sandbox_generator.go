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
	"slices"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// SandboxGenerator serves complete inline policy snapshots from the same immutable
// publication. Scope is recomputed from Sandbox attesters, never from a UID claimed
// in a subscribe request. Gateways retain their existing cluster discovery scope.
type SandboxGenerator struct{}

// Generate returns the Sandbox delta visible to the authenticated client scope.
func (SandboxGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.SandboxType {
		return GeneratedDelta{}, fmt.Errorf("sandbox generator does not support type URL %q", request.TypeURL)
	}
	if request.Full || request.Update.FullFor(request.TypeURL) {
		selected := selectSandboxResources(request.Scope, request.Snapshot, request.TypeURL, request.Subscription)
		delta := diffSelected(request.Subscription, selected)
		// A repeated subscribe may mean the client evicted its local copy.
		for _, name := range request.SubscribedNames {
			if name == "*" {
				continue
			}
			if r, ok := selected[name]; ok {
				if !slices.ContainsFunc(delta.Resources, func(r model.Resource) bool { return r.XDSName == name }) {
					delta.Resources = append(delta.Resources, r)
				}
			} else if !slices.Contains(delta.Removed, name) {
				delta.Removed = append(delta.Removed, name)
			}
		}
		return delta, nil
	}
	// Recompute visibility when attester Workloads change; policy body changes
	// are ordinary updates of their owning Sandbox resource.
	scopeChanged := scopedWorkloadChanged(request.Scope, request.Update)
	if request.Scope.Class == model.ClientEgressGateway {
		scopeChanged = false
	}
	if !scopeChanged {
		changes := request.Update.ReadOnlyChangesForType(request.TypeURL)
		if !request.Subscription.Wildcard() {
			changes = request.Update.ChangesForNames(request.TypeURL, request.Subscription.Names())
		}
		candidates := sets.New[model.ResourceKey]()
		for _, change := range changes {
			candidates.Insert(change.Key)
		}
		visible := func(snapshot model.ResourceSet) func(model.Resource) bool {
			return func(r model.Resource) bool {
				return request.Subscription.allows(r) && sandboxVisible(request.Scope, snapshot, r.Key.Name)
			}
		}

		selected, removed := diffCandidateTransition(candidates, request.Update.Before().Get, request.Update.After().Get,
			visible(request.Update.Before()), visible(request.Update.After()))
		return newSortedDelta(selected, removed, false), nil
	}
	before := selectSandboxResources(request.Scope, request.Update.Before(), request.TypeURL, request.Subscription)
	after := selectSandboxResources(request.Scope, request.Update.After(), request.TypeURL, request.Subscription)
	selected := make(map[string]model.Resource)
	removed := sets.New[string]()
	for name, r := range after {
		if old, ok := before[name]; !ok || old.Hash != r.Hash {
			selected[name] = r
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			removed.Insert(name)
		}
	}
	return newSortedDelta(selected, removed, false), nil
}

func scopedSandboxNames(scope model.ClientScope, snapshot model.ResourceSet) sets.Set[string] {
	result := sets.New[string]()
	for _, workload := range scopedWorkloads(scope, snapshot, model.AddressType) {
		for _, sandbox := range snapshot.ListSandboxesByAttester(workload.Facts.Workload.WorkloadUID) {
			result.Insert(sandbox.Key.Name)
		}
	}
	return result
}

func sandboxVisible(scope model.ClientScope, snapshot model.ResourceSet, uid string) bool {
	sandbox, found := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid})
	return found && sandboxResourceVisible(scope, snapshot, sandbox)
}

func sandboxResourceVisible(scope model.ClientScope, snapshot model.ResourceSet, sandbox model.Resource) bool {
	if scope.Class == model.ClientEgressGateway {
		return true
	}
	facts := sandbox.Facts.Sandbox
	if facts == nil || facts.AttesterWorkloadUID == "" {
		return false
	}
	query, ok := workloadScopeQuery(scope)
	if !ok || (query.WorkloadUID != "" && query.WorkloadUID != facts.AttesterWorkloadUID) {
		return false
	}
	query.WorkloadUID = facts.AttesterWorkloadUID
	return snapshot.HasWorkload(model.AddressType, query)
}

func sandboxGatewayReferenceKeys(snapshot model.ResourceSet, workloads []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, workload := range workloads {
		for _, sandbox := range snapshot.ListSandboxesByAttester(workload.Facts.Workload.WorkloadUID) {
			result.InsertAll(sandbox.Facts.Sandbox.GatewayReferences...)
		}
	}
	return result
}

func selectSandboxResources(scope model.ClientScope, snapshot model.ResourceSet, typeURL string, sub SubscriptionView) map[string]model.Resource {
	result := make(map[string]model.Resource)
	add := func(r model.Resource) {
		if sub.allows(r) {
			result[r.XDSName] = r
		}
	}
	if scope.Class == model.ClientEgressGateway {
		if sub.Wildcard() {
			for _, r := range snapshot.List(typeURL) {
				add(r)
			}
		} else {
			for _, name := range sub.Names() {
				for _, r := range snapshot.Lookup(typeURL, name) {
					add(r)
				}
			}
		}
		return result
	}
	if typeURL == model.SandboxType && !sub.Wildcard() {
		for _, uid := range sub.Names() {
			if !sandboxVisible(scope, snapshot, uid) {
				continue
			}
			if r, ok := snapshot.Get(model.ResourceKey{TypeURL: typeURL, Name: uid}); ok {
				add(r)
			}
		}
		return result
	}
	for uid := range scopedSandboxNames(scope, snapshot) {
		if r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid}); ok {
			add(r)
		}
	}
	return result
}
