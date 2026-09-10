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
	"runtime"
	"slices"
	"testing"

	"istio.io/istio/pkg/util/sets"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestAuthorizationSelectionIncludesGlobalNamespaceAndWorkloadSelector(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-b", "", "other/selector-b"),
		selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, ""),
		selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo"),
		selectionAuthorization(t, "other/namespace", model.AuthorizationScopeNamespace, "other"),
		selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, ""),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		SourceUID:   "uid-a",
	}

	got := selectAuthorizationResources(scope, snapshot, nil)
	want := []string{"agentio-system/global", "demo/namespace", "demo/selector-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("selected authorizations = %v, want %v", names, want)
	}
}

func TestNodeAuthorizationSelectionUsesLocalWorkloadFacts(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-a", "", "other/selector-b"),
		selectionWorkload(t, "uid-c", "remote", "node-b", "", "remote/selector-c"),
		selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, ""),
		selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo"),
		selectionAuthorization(t, "other/namespace", model.AuthorizationScopeNamespace, "other"),
		selectionAuthorization(t, "remote/namespace", model.AuthorizationScopeNamespace, "remote"),
		selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "remote/selector-c", model.AuthorizationScopeWorkload, ""),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectAuthorizationResources(scope, snapshot, nil)
	want := []string{
		"agentio-system/global", "demo/namespace", "demo/selector-a", "other/namespace", "other/selector-b",
	}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("selected node authorizations = %v, want %v", names, want)
	}
}

func TestGatewayNamedAuthorizationSelectionDoesNotAllocateSnapshotScale(t *testing.T) {
	const resourceCount = 10_000
	const runs = 10
	var before, after runtime.MemStats
	var selected []model.Resource
	authorizationValue := mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: "policy"})
	authorizations := make([]model.Resource, 0, resourceCount+1)
	for i := range resourceCount {
		name := fmt.Sprintf("unrelated-policy-%06d", i)
		authorizations = append(authorizations, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name},
			XDSName: name,
			Value:   authorizationValue,
			Hash:    name,
			Facts:   model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeWorkload}},
		})
	}
	target := selectionAuthorization(t, "demo/target", model.AuthorizationScopeWorkload, "")
	authorizations = append(authorizations, target, selectionWorkload(t, "target-workload", "demo", "node-a", "", target.XDSName))
	authorizationSnapshot := selectionSnapshot(t, authorizations)
	runtime.GC()
	runtime.ReadMemStats(&before)
	allocations := testing.AllocsPerRun(runs, func() {
		selected = selectAuthorizationResources(gatewayScope(), authorizationSnapshot, []string{target.XDSName})
	})
	runtime.ReadMemStats(&after)
	if names := selectedNames(selected); !slices.Equal(names, []string{target.XDSName}) {
		t.Fatalf("selected authorizations = %v, want target only", names)
	}
	if allocations > 32 {
		t.Fatalf("named gateway authorization allocations = %.1f/run, want <= 32", allocations)
	}
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 64<<10 {
		t.Fatalf("named gateway authorization allocated %d bytes/run, want <= %d", bytesPerRun, 64<<10)
	}
}

func TestUnrelatedWorkloadAddressChangeDoesNotReconcileAuthorization(t *testing.T) {
	owned := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a")
	oldUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "", "other/selector-b")
	newUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", "other/selector-b")
	before := selectionSnapshot(t, []model.Resource{owned, oldUnrelated})
	after := selectionSnapshot(t, []model.Resource{owned, newUnrelated})
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldUnrelated.Key,
		Old: &oldUnrelated,
		New: &newUnrelated,
	}})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		SourceUID:   "uid-a",
	}

	delta, err := (AuthorizationGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("unrelated change produced resources=%v removed=%v", selectedNames(delta.Resources), delta.Removed)
	}
}

func TestGatewayAuthorizationIncrementalAllowsNonGlobalPolicy(t *testing.T) {
	oldResource := selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, "")
	newResource, err := model.NewResource(
		oldResource.Key, oldResource.XDSName,
		mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: "selector-a", Namespace: "demo"}),
		oldResource.Aliases, oldResource.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, "")
	snapshot := selectionSnapshot(t, []model.Resource{newResource, unrelated, selectionWorkload(t, "ordinary", "demo", "node-a", "", "demo/selector-a")})
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{oldResource.XDSName: oldResource.Hash, unrelated.XDSName: unrelated.Hash},
	}
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldResource.Key,
		Old: &oldResource,
		New: &newResource,
	}})
	view := newIncrementalSubscriptionView(watch, model.WorkloadAuthorizationType, update)
	if names := view.SentNames(); !slices.Equal(names, []string{oldResource.XDSName}) {
		t.Fatalf("gateway incremental sent-state = %v, want only changed authorization", names)
	}

	delta, err := (AuthorizationGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        gatewayScope(),
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"demo/selector-a"}) {
		t.Fatalf("incremental gateway authorizations = %v, want updated selector policy", names)
	}
}
