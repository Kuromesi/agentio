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

// TrafficPolicyGenerator serves shared policies referenced by authorized
// Sandboxes. Named subscriptions never widen that owner scope.
type TrafficPolicyGenerator struct{}

// Generate returns shared policy updates visible to the requesting client.
func (TrafficPolicyGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.TrafficPolicyType {
		return GeneratedDelta{}, fmt.Errorf("traffic policy generator does not support type URL %q", request.TypeURL)
	}
	if request.Full || request.Update.FullFor(request.TypeURL) {
		selected := selectTrafficPolicyResources(request.Scope, request.Snapshot, request.Subscription)
		return diffSubscribed(request.Subscription, selected, request.SubscribedNames), nil
	}
	candidates := sets.New[model.ResourceKey]()
	for _, change := range request.Update.ReadOnlyChangesForType(request.TypeURL) {
		candidates.Insert(change.Key)
	}
	// Derived visibility changes may not include a TrafficPolicy body change.
	// Diff the publications directly; incremental subscription views only carry
	// sent versions for changed bodies, not for these derived candidates.
	if request.Scope.Class != model.ClientEgressGateway && scopedWorkloadChanged(request.Scope, request.Update) {
		for _, snapshot := range []model.ResourceSet{request.Update.Before(), request.Update.After()} {
			for _, resource := range selectTrafficPolicyResources(request.Scope, snapshot, request.Subscription) {
				candidates.Insert(resource.Key)
			}
		}
	} else {
		for _, change := range request.Update.ReadOnlyChangesForType(model.SandboxType) {
			for _, resource := range []*model.Resource{change.Old, change.New} {
				if resource == nil || resource.Facts.Sandbox == nil {
					continue
				}
				for _, name := range resource.Facts.Sandbox.TrafficPolicyRefs {
					candidates.Insert(model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name})
				}
			}
		}
	}
	visible := func(snapshot model.ResourceSet) func(model.Resource) bool {
		var names sets.Set[string]
		if request.Scope.Class != model.ClientEgressGateway {
			names = scopedTrafficPolicyNames(request.Scope, snapshot)
		}
		return func(resource model.Resource) bool {
			if !request.Subscription.allows(resource) {
				return false
			}
			if request.Scope.Class == model.ClientEgressGateway {
				return snapshot.HasTrafficPolicyReference(resource.Key.Name)
			}
			return names.Contains(resource.Key.Name)
		}
	}
	resources, removed := diffCandidateTransition(candidates, request.Update.Before().Get, request.Update.After().Get,
		visible(request.Update.Before()), visible(request.Update.After()))
	return newSortedDelta(resources, removed, false), nil
}

func selectTrafficPolicyResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	sub SubscriptionView,
) map[string]model.Resource {
	selected := make(map[string]model.Resource)
	for name := range scopedTrafficPolicyNames(scope, snapshot) {
		if resource, ok := snapshot.Get(
			model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name},
		); ok &&
			sub.allows(resource) {
			selected[resource.XDSName] = resource
		}
	}
	return selected
}

func scopedTrafficPolicyNames(scope model.ClientScope, snapshot model.ResourceSet) sets.Set[string] {
	names := sets.New[string]()
	add := func(sandbox model.Resource) {
		if sandbox.Facts.Sandbox != nil {
			names.InsertAll(sandbox.Facts.Sandbox.TrafficPolicyRefs...)
		}
	}
	if scope.Class == model.ClientEgressGateway {
		for _, sandbox := range snapshot.List(model.SandboxType) {
			add(sandbox)
		}
	} else {
		for uid := range scopedSandboxNames(scope, snapshot) {
			if sandbox, ok := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid}); ok {
				add(sandbox)
			}
		}
	}
	return names
}
