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
	"slices"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestAuthorizationVisibilityUsesScopedIdentityAndExactReferences(t *testing.T) {
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/exact")
	global := selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, "")
	namespace := selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo")
	exact := selectionAuthorization(t, "demo/exact", model.AuthorizationScopeWorkload, "")
	unrelated := selectionAuthorization(t, "other/unrelated", model.AuthorizationScopeNamespace, "other")
	visibility := newAuthorizationVisibility(
		model.ClientScope{Class: model.ClientDedicatedZTunnel, Principal: serviceAccountPrincipal("demo", "default"), WorkloadUID: "uid-a", SourceUID: "uid-a"},
		selectionSnapshot(t, []model.Resource{workload, global, namespace, exact, unrelated}),
	)

	for _, resource := range []model.Resource{global, namespace, exact} {
		if !visibility.visible(resource) {
			t.Errorf("authorization %q is not visible", resource.XDSName)
		}
	}
	if visibility.visible(unrelated) {
		t.Fatalf("unrelated authorization %q is visible", unrelated.XDSName)
	}
}

func TestAuthorizationIncrementalDiffsExactReferenceTransition(t *testing.T) {
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/old")
	newWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/new")
	oldPolicy := selectionAuthorization(t, "demo/old", model.AuthorizationScopeWorkload, "")
	newPolicy := selectionAuthorization(t, "demo/new", model.AuthorizationScopeWorkload, "")
	before := selectionSnapshot(t, []model.Resource{oldWorkload, oldPolicy, newPolicy})
	after := selectionSnapshot(t, []model.Resource{newWorkload, oldPolicy, newPolicy})
	request := GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientDedicatedZTunnel, Principal: serviceAccountPrincipal("demo", "default"), WorkloadUID: "uid-a", SourceUID: "uid-a"},
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after,
		Update: updateBetween(before, after, []model.ResourceChange{{
			Key: oldWorkload.Key,
			Old: &oldWorkload,
			New: &newWorkload,
		}}),
	}

	delta := generateAuthorizationIncremental(request)
	if got, want := selectedNames(delta.Resources), []string{"demo/new"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization resources = %v, want %v", got, want)
	}
	if got, want := delta.Removed, []string{"demo/old"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization removals = %v, want %v", got, want)
	}
}

func TestAuthorizationExcludesSandboxManagedEndpoints(t *testing.T) {
	host := selectionWorkload(t, "host", "sandbox-ns", "node-a", "", "sandbox-ns/exact")
	facts := *host.Facts.Workload
	facts.SandboxManaged = true
	var err error
	host, err = model.NewResource(host.Key, host.XDSName, host.Value, host.Aliases, model.ResourceFacts{Workload: &facts})
	if err != nil {
		t.Fatal(err)
	}
	ordinary := selectionWorkload(t, "ordinary", "pod-ns", "node-a", "", "pod-ns/exact")
	policies := []model.Resource{
		selectionAuthorization(t, "global", model.AuthorizationScopeGlobal, ""),
		selectionAuthorization(t, "sandbox-ns/baseline", model.AuthorizationScopeNamespace, "sandbox-ns"),
		selectionAuthorization(t, "sandbox-ns/exact", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "pod-ns/baseline", model.AuthorizationScopeNamespace, "pod-ns"),
		selectionAuthorization(t, "pod-ns/exact", model.AuthorizationScopeWorkload, ""),
	}
	before := selectionSnapshot(t, append([]model.Resource{host, ordinary}, policies...))
	after := selectionSnapshot(t, append([]model.Resource{host}, policies...))
	update := updateBetween(before, after, before.Diff(after))
	scopes := []model.ClientScope{
		{Class: model.ClientDedicatedZTunnel, WorkloadUID: "host", SourceUID: "host", Principal: host.Facts.Workload.Principal},
		{Class: model.ClientDedicatedZTunnel, WorkloadUID: "ordinary", SourceUID: "ordinary", Principal: ordinary.Facts.Workload.Principal},
		{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		gatewayScope(),
	}
	for _, scope := range scopes {
		want := []string{"global", "pod-ns/baseline", "pod-ns/exact"}
		if scope.WorkloadUID == "host" {
			want = nil
		}
		for _, names := range [][]string{nil, {"global", "pod-ns/baseline", "pod-ns/exact", "sandbox-ns/baseline", "sandbox-ns/exact"}} {
			if got := selectedNames(selectAuthorizationResources(scope, before, names)); !slices.Equal(got, want) {
				t.Fatalf("scope %+v got %v, want %v", scope, got, want)
			}
			if got := selectAuthorizationResources(scope, after, names); len(got) != 0 {
				t.Fatalf("Sandbox-only scope received Workload policies: %v", selectedNames(got))
			}
			delta := generateAuthorizationIncremental(GenerationRequest{
				Scope:        scope,
				TypeURL:      model.WorkloadAuthorizationType,
				Subscription: SubscriptionView{wildcard: names == nil, names: names},
				Snapshot:     after,
				Update:       update,
			})
			if len(delta.Resources) != 0 || !slices.Equal(delta.Removed, want) {
				t.Fatalf("removing last ordinary endpoint: %+v, want removals %v", delta, want)
			}
		}
		// A policy-only update must also respect the endpoint classification.
		changed, err := model.NewResource(policies[0].Key, "", policies[0].Value, []string{"updated"}, policies[0].Facts)
		if err != nil {
			t.Fatal(err)
		}
		latest, _, err := after.Apply([]model.ResourceChange{{Key: changed.Key, Old: &policies[0], New: &changed}})
		if err != nil {
			t.Fatal(err)
		}
		delta := generateAuthorizationIncremental(GenerationRequest{
			Scope:        scope,
			TypeURL:      model.WorkloadAuthorizationType,
			Subscription: SubscriptionView{wildcard: true},
			Snapshot:     latest,
			Update:       updateBetween(after, latest, after.Diff(latest)),
		})
		if len(delta.Resources) != 0 {
			t.Fatalf("policy-only update leaked to Sandbox hosts: %+v", delta)
		}
	}
}
