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
	"slices"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestDiscoveryViewVisibilityFollowsScopedWorkloads(t *testing.T) {
	owned := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		"agentio-system/egress-a")
	sameNode := selectionWorkload(t, "uid-b", "other", "node-a", "svc-b", "")
	remote := selectionWorkload(t, "uid-c", "remote", "node-b", "svc-c", "")
	serviceA := selectionService(t, "demo/svc-a")
	serviceB := selectionService(t, "demo/svc-b")
	serviceC := selectionService(t, "demo/svc-c")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""),
		"agentio-system/egress-a")
	snapshot := selectionSnapshot(t, []model.Resource{
		owned, sameNode, remote, serviceA, serviceB, serviceC, gateway,
	})

	dedicated := newDiscoveryView(
		model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"},
		snapshot, model.AddressType,
	)
	if !dedicated.visible(owned) || dedicated.visible(sameNode) || dedicated.visible(remote) {
		t.Fatal("dedicated Workload visibility did not follow the sandbox scope")
	}
	if !dedicated.visible(serviceA) || dedicated.visible(serviceB) {
		t.Fatal("dedicated Service visibility did not follow its scoped Workload")
	}
	if !dedicated.visible(gateway) {
		t.Fatal("referenced Gateway workload is not visible")
	}
	if got := selectedNames(dedicated.ownedByGateway("agentio-system/egress-a")); !slices.Equal(got, []string{"gateway-a"}) {
		t.Fatalf("Gateway-owned resources = %v, want gateway-a", got)
	}

	node := newDiscoveryView(
		model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		snapshot, model.AddressType,
	)
	if !node.visible(owned) || !node.visible(sameNode) || node.visible(remote) {
		t.Fatal("node Workload visibility did not follow the node scope")
	}
	if !node.visible(serviceB) || node.visible(serviceC) {
		t.Fatal("node Service visibility did not follow its scoped Workloads")
	}
}

func TestWildcardWDSDirtyDiffsPublicationTransitionClosure(t *testing.T) {
	plain := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	attached := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		"agentio-system/egress-a")
	service := selectionService(t, "demo/svc-a")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""),
		"agentio-system/egress-a")
	before := selectionSnapshot(t, []model.Resource{plain, service, gateway})
	after := selectionSnapshot(t, []model.Resource{attached, service, gateway})
	scope := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"}

	added, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after,
		Update: updateBetween(before, after, []model.ResourceChange{{
			Key: plain.Key, Old: &plain, New: &attached,
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := selectedNames(added.Resources), []string{"demo/svc-a", "gateway-a", "uid-a"}; !slices.Equal(got, want) || len(added.Removed) != 0 {
		t.Fatalf("reference addition resources=%v removed=%v, want resources=%v", got, added.Removed, want)
	}

	removed, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     before,
		Update: updateBetween(after, before, []model.ResourceChange{{
			Key: plain.Key, Old: &attached, New: &plain,
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := selectedNames(removed.Resources), []string{"uid-a"}; !slices.Equal(got, want) {
		t.Fatalf("reference removal resources=%v, want %v", got, want)
	}
	slices.Sort(removed.Removed)
	if got, want := removed.Removed, []string{"demo/svc-a", "gateway-a"}; !slices.Equal(got, want) {
		t.Fatalf("reference removal removed=%v, want %v", got, want)
	}
}

func TestAuthorizationViewUsesScopedIdentityAndExactReferences(t *testing.T) {
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/exact")
	global := selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, "")
	namespace := selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo")
	exact := selectionAuthorization(t, "demo/exact", model.AuthorizationScopeWorkload, "")
	unrelated := selectionAuthorization(t, "other/unrelated", model.AuthorizationScopeNamespace, "other")
	view := newAuthorizationView(
		model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"},
		selectionSnapshot(t, []model.Resource{workload, global, namespace, exact, unrelated}),
	)

	for _, resource := range []model.Resource{global, namespace, exact} {
		if !view.visible(resource) {
			t.Errorf("authorization %q is not visible", resource.XDSName)
		}
	}
	if view.visible(unrelated) {
		t.Fatalf("unrelated authorization %q is visible", unrelated.XDSName)
	}
}

func TestAuthorizationDirtyDiffsExactReferenceTransition(t *testing.T) {
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/old")
	newWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/new")
	oldPolicy := selectionAuthorization(t, "demo/old", model.AuthorizationScopeWorkload, "")
	newPolicy := selectionAuthorization(t, "demo/new", model.AuthorizationScopeWorkload, "")
	before := selectionSnapshot(t, []model.Resource{oldWorkload, oldPolicy, newPolicy})
	after := selectionSnapshot(t, []model.Resource{newWorkload, oldPolicy, newPolicy})
	request := GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"},
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after,
		Update: updateBetween(before, after, []model.ResourceChange{{
			Key: oldWorkload.Key, Old: &oldWorkload, New: &newWorkload,
		}}),
	}

	delta := generateAuthorizationDirty(request)
	if got, want := selectedNames(delta.Resources), []string{"demo/new"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization resources = %v, want %v", got, want)
	}
	if got, want := delta.Removed, []string{"demo/old"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization removals = %v, want %v", got, want)
	}
}
