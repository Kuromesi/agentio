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

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

func TestOrderedUniquePreservesLastResourceForDuplicateKey(t *testing.T) {
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "duplicate"}
	first := model.Resource{Key: key, XDSName: "wire-b", Hash: "first"}
	last := model.Resource{Key: key, XDSName: "wire-a", Hash: "last"}
	other := model.Resource{
		Key:     model.ResourceKey{TypeURL: model.AddressType, Name: "other"},
		XDSName: "wire-z",
		Hash:    "other",
	}

	got := orderedUnique([]model.Resource{first, other, last})
	if len(got) != 2 || got[0].Key != key || got[0].Hash != "last" || got[1].Key != other.Key {
		t.Fatalf("orderedUnique() = %#v, want last duplicate followed by other", got)
	}
}

func TestDedicatedZTunnelReceivesOnlySandboxScope(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", "other/selector-b"),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionService(t, "other/svc-b", "/10.96.0.2"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:      model.ClientDedicatedZTunnel,
		Principal:  serviceAccountPrincipal("demo", "client-a"),
		SandboxUID: "uid-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("selected resources = %v, want own workload and service", names)
	}
}

func TestSandboxReferencedGatewaySelection(t *testing.T) {
	own := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""), "agentio-system/egress-a")
	other := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", ""), "other/egress-b")
	gatewayAWorkload := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	gatewayAService := selectionOwnedByGateway(t,
		selectionService(t, "agentio-system/egress-a.agentio-system.svc.cluster.local"), "agentio-system/egress-a")
	gatewayBWorkload := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-b", "other", "gateway-node", "", ""), "other/egress-b")
	gatewayBService := selectionOwnedByGateway(t,
		selectionService(t, "other/egress-b.other.svc.cluster.local"), "other/egress-b")
	snapshot := selectionSnapshot(t, []model.Resource{
		own, other, selectionService(t, "demo/svc-a"), selectionService(t, "other/svc-b"),
		gatewayAWorkload, gatewayAService, gatewayBWorkload, gatewayBService,
		selectionWorkload(t, "unrelated", "unrelated", "node-z", "", ""),
	})
	scope := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	want := []string{"agentio-system/egress-a.agentio-system.svc.cluster.local", "demo/svc-a", "gateway-a", "uid-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("wildcard selected resources = %v, want %v", names, want)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"})
	want = []string{"agentio-system/egress-a.agentio-system.svc.cluster.local", "gateway-a", "uid-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("named selected resources = %v, want %v", names, want)
	}
}

func TestNodeReferencedGatewaySelection(t *testing.T) {
	localA := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "", ""), "agentio-system/egress-a")
	localB := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-b", "demo", "node-a", "", ""), "agentio-system/egress-b")
	remote := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-c", "other", "node-b", "", ""), "other/egress-c")
	resources := []model.Resource{localA, localB, remote}
	for _, gateway := range []struct{ uid, key string }{
		{uid: "gateway-a", key: "agentio-system/egress-a"},
		{uid: "gateway-b", key: "agentio-system/egress-b"},
		{uid: "gateway-c", key: "other/egress-c"},
	} {
		resources = append(resources, selectionOwnedByGateway(t,
			selectionWorkload(t, gateway.uid, "agentio-system", "gateway-node", "", ""), gateway.key))
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	if names := selectedNames(selectWorkloadResources(scope, snapshot, model.AddressType, nil)); !slices.Equal(names, []string{"gateway-a", "gateway-b", "uid-a", "uid-b"}) {
		t.Fatalf("node selected resources = %v", names)
	}
}

func TestNamedSandboxAlwaysIncludesReferencedGateways(t *testing.T) {
	own := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "", ""), "agentio-system/egress-a")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	snapshot := selectionSnapshot(t, []model.Resource{own, gateway})
	scope := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"}
	if names := selectedNames(selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"})); !slices.Equal(names, []string{"gateway-a", "uid-a"}) {
		t.Fatalf("named selection = %v", names)
	}
}

func TestNamedReferencedGatewayDirty(t *testing.T) {
	scope := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"}
	plain := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	own := selectionWithGatewayReference(t, plain, "agentio-system/egress-a")
	oldGateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	newGateway, err := model.NewResource(oldGateway.Key, oldGateway.XDSName, oldGateway.Value,
		[]string{"revision/two"}, oldGateway.Facts)
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot := selectionSnapshot(t, []model.Resource{own, oldGateway})
	newSnapshot := selectionSnapshot(t, []model.Resource{own, newGateway})
	watch := &watchState{
		names:   sets.New("uid-a"),
		started: true,
		sent:    map[string]string{"uid-a": own.Hash, "gateway-a": oldGateway.Hash},
	}
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))
	view := newDirtySubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.AddressType, Subscription: view, Snapshot: newSnapshot, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"gateway-a"}) || len(delta.Removed) != 0 {
		t.Fatalf("gateway payload delta resources=%v removed=%v", names, delta.Removed)
	}

	withoutReference := selectionSnapshot(t, []model.Resource{plain, newGateway})
	watch.sent = map[string]string{"uid-a": own.Hash, "gateway-a": newGateway.Hash}
	update = updateBetween(newSnapshot, withoutReference, newSnapshot.Diff(withoutReference))
	view = newDirtySubscriptionView(watch, model.AddressType, update)
	delta, err = (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.AddressType, Subscription: view, Snapshot: withoutReference, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-a"}) ||
		!slices.Equal(delta.Removed, []string{"gateway-a"}) {
		t.Fatalf("reference removal delta resources=%v removed=%v", names, delta.Removed)
	}
}

func TestSharedZTunnelReceivesNodeWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "other", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-c", "other", "node-b", "svc-b", ""),
		selectionService(t, "demo/svc-a"),
		selectionService(t, "other/svc-b"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want node-local workloads and their service", names)
	}
}

func TestSharedZTunnelWorkloadTypeReceivesOnlyNodeWorkloads(t *testing.T) {
	snapshot := selectionSnapshot(t, []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", ""),
	})
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := projectedWorkloads(t, scope, snapshot, nil)
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a"}) {
		t.Fatalf("selected Workload resources = %v, want node-local workload", names)
	}
}

func TestNodeNamedSubscriptionAddsLocalAndExplicitRemoteWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-a", "svc-b", ""),
		selectionWorkload(t, "uid-c", "demo", "node-b", "svc-a", ""),
		selectionWorkload(t, "uid-d", "demo", "node-b", "svc-c", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionService(t, "demo/svc-b", "/10.96.0.2"),
		selectionService(t, "demo/svc-c", "/10.96.0.3"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a", "uid-b"}) {
		t.Fatalf("selected named Address resources = %v, want all node-local workloads only", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-c"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a", "uid-b", "uid-c"}) {
		t.Fatalf("selected remote Address resource = %v, want explicit remote workload plus node-local workloads", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b", "uid-c"}) {
		t.Fatalf("selected VIP Address resources = %v, want subscribed service, every endpoint, and node-local workloads", names)
	}

	got = projectedWorkloads(t, scope, snapshot, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a", "uid-b", "uid-c"}) {
		t.Fatalf("selected VIP Workload resources = %v, want every endpoint and node-local workloads", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.3"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-c", "uid-a", "uid-b", "uid-d"}) {
		t.Fatalf("selected remote-only Service resources = %v, want its remote endpoint and node-local workloads", names)
	}
}

func TestWorkloadTypeNamedServiceResolvesAddressAlias(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-b", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)

	got := projectedWorkloads(t, gatewayScope(), snapshot, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a"}) {
		t.Fatalf("selected Workload resources = %v, want service endpoint resolved through Address alias", names)
	}
}

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
		Class:      model.ClientDedicatedZTunnel,
		Principal:  serviceAccountPrincipal("demo", "client-a"),
		SandboxUID: "uid-a",
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

func TestNamedServiceSubscriptionExpandsSelectedEndpointWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:      model.ClientDedicatedZTunnel,
		Principal:  serviceAccountPrincipal("demo", "client-a"),
		SandboxUID: "uid-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("selected resources = %v, want service and selected endpoint workload", names)
	}
}

func TestGatewayNamedServiceSubscriptionExpandsAllEndpoints(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)

	got := selectWorkloadResources(gatewayScope(), snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want service and all endpoints", names)
	}
}

func TestGatewayNamedSelectionDoesNotAllocateSnapshotScale(t *testing.T) {
	const resourceCount = 10_000
	value := mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{}}})
	resources := make([]model.Resource, 0, resourceCount+3)
	for i := range resourceCount {
		name := fmt.Sprintf("unrelated-%06d", i)
		resources = append(resources, model.Resource{
			Key: model.ResourceKey{TypeURL: model.AddressType, Name: name}, XDSName: name,
			Value: value, Hash: name,
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: name, NodeName: "node-a", Principal: serviceAccountPrincipal("demo", "default"),
			}},
		})
	}
	resources = append(resources,
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
	)
	snapshot := selectionSnapshot(t, resources)

	const runs = 10
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var selected []model.Resource
	allocations := testing.AllocsPerRun(runs, func() {
		selected = selectWorkloadResources(gatewayScope(), snapshot, model.AddressType, []string{"/10.96.0.1"})
	})
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if names := selectedNames(selected); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want target service and endpoints", names)
	}
	if allocations > 64 {
		t.Fatalf("named gateway selection allocations = %.1f/run, want <= 64", allocations)
	}
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 256<<10 {
		t.Fatalf("named gateway selection allocated %d bytes/run, want <= %d", bytesPerRun, 256<<10)
	}

	authorizationValue := mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: "policy"})
	authorizations := make([]model.Resource, 0, resourceCount+1)
	for i := range resourceCount {
		name := fmt.Sprintf("unrelated-policy-%06d", i)
		authorizations = append(authorizations, model.Resource{
			Key: model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}, XDSName: name,
			Value: authorizationValue, Hash: name,
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeWorkload}},
		})
	}
	target := selectionAuthorization(t, "demo/target", model.AuthorizationScopeWorkload, "")
	authorizations = append(authorizations, target)
	authorizationSnapshot := selectionSnapshot(t, authorizations)
	runtime.GC()
	runtime.ReadMemStats(&before)
	allocations = testing.AllocsPerRun(runs, func() {
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

func TestUnrelatedGatewayNamedServiceAddressChangeDoesNotReconcile(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	endpoint := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	oldUnrelated := selectionWorkload(t, "uid-b", "demo", "node-b", "svc-b", "")
	newUnrelated, err := model.NewResource(
		oldUnrelated.Key, oldUnrelated.XDSName, oldUnrelated.Value,
		[]string{"uid-b-alias"}, oldUnrelated.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	before := selectionSnapshot(t, []model.Resource{service, endpoint, oldUnrelated})
	after := selectionSnapshot(t, []model.Resource{service, endpoint, newUnrelated})
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldUnrelated.Key, Old: &oldUnrelated, New: &newUnrelated,
	}})
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: gatewayScope(), TypeURL: model.AddressType,
		Subscription: SubscriptionView{names: []string{"/10.96.0.1"}},
		Snapshot:     after, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("unrelated change produced resources=%v removed=%v", selectedNames(delta.Resources), delta.Removed)
	}
}

func TestUnrelatedSandboxAddressChangeDoesNotReconcileAuthorization(t *testing.T) {
	owned := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a")
	oldUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "", "other/selector-b")
	newUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", "other/selector-b")
	before := selectionSnapshot(t, []model.Resource{owned, oldUnrelated})
	after := selectionSnapshot(t, []model.Resource{owned, newUnrelated})
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldUnrelated.Key, Old: &oldUnrelated, New: &newUnrelated,
	}})
	scope := model.ClientScope{
		Class:      model.ClientDedicatedZTunnel,
		Principal:  serviceAccountPrincipal("demo", "client-a"),
		SandboxUID: "uid-a",
	}

	delta, err := (AuthorizationGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("unrelated change produced resources=%v removed=%v", selectedNames(delta.Resources), delta.Removed)
	}
}

func TestNodeNamedServiceRemotePayloadUpdateUsesDirtyKey(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	local := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
	oldRemote := selectionWorkload(t, "uid-remote", "demo", "node-b", "svc-a", "")
	newRemote, err := model.NewResource(
		oldRemote.Key, oldRemote.XDSName,
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid: "uid-remote", Namespace: "demo", Node: "node-b", Name: "updated",
		}}}),
		oldRemote.Aliases, oldRemote.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := selectionSnapshot(t, []model.Resource{service, local, newRemote})
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldRemote.Key, Old: &oldRemote, New: &newRemote,
	}})
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	sent := make(map[string]string, 10_002)
	for i := range 10_000 {
		sent[fmt.Sprintf("unrelated-%05d", i)] = "v1"
	}
	sent[service.XDSName] = service.Hash
	sent[local.XDSName] = local.Hash
	sent[oldRemote.XDSName] = oldRemote.Hash
	watch := &watchState{
		started: true, names: sets.New(service.Aliases[0]), sent: sent,
	}

	view := newDirtySubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.AddressType, Subscription: view, Snapshot: snapshot, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-remote"}) {
		t.Fatalf("remote payload-only delta resources = %v, want uid-remote", names)
	}
	if len(delta.Removed) != 0 {
		t.Fatalf("remote payload-only removals = %v, want empty", delta.Removed)
	}
}

func TestNodeNamedServiceRemoteToLocalMoveUpdatesWorkload(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	local := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
	oldRemote := selectionWorkload(t, "uid-remote", "demo", "node-b", "svc-a", "")
	newLocal := selectionWorkload(t, "uid-remote", "demo", "node-a", "svc-a", "")
	snapshot := selectionSnapshot(t, []model.Resource{service, local, newLocal})
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldRemote.Key, Old: &oldRemote, New: &newLocal,
	}})
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	watch := &watchState{
		started: true, names: sets.New(service.Aliases[0]),
		sent: map[string]string{
			service.XDSName: service.Hash, local.XDSName: local.Hash, oldRemote.XDSName: oldRemote.Hash,
		},
	}

	view := newDirtySubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.AddressType, Subscription: view, Snapshot: snapshot, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-remote"}) {
		t.Fatalf("remote-to-local delta resources = %v, want uid-remote", names)
	}
	if len(delta.Removed) != 0 {
		t.Fatalf("remote-to-local removals = %v, want none", delta.Removed)
	}
}

func TestSandboxNamedServiceMembershipLossReconcilesRemovals(t *testing.T) {
	for _, client := range []struct {
		name  string
		class model.ClientClass
	}{
		{name: "sandbox", class: model.ClientDedicatedZTunnel},
	} {
		for _, transition := range []string{"local-to-remote", "delete", "detach-service"} {
			t.Run(client.name+"/"+transition, func(t *testing.T) {
				service := selectionService(t, "demo/svc-a", "/10.96.0.1")
				oldWorkload := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
				var newWorkload *model.Resource
				switch transition {
				case "local-to-remote":
					facts := oldWorkload.Facts
					workloadFacts := *facts.Workload
					workloadFacts.SandboxUID = "uid-other"
					facts.Workload = &workloadFacts
					updated, err := model.NewResource(
						oldWorkload.Key, oldWorkload.XDSName, oldWorkload.Value,
						oldWorkload.Aliases, facts,
					)
					if err != nil {
						t.Fatal(err)
					}
					newWorkload = &updated
				case "delete":
				case "detach-service":
					updated := selectionWorkload(t, "uid-local", "demo", "node-a", "", "")
					newWorkload = &updated
				default:
					t.Fatalf("unknown transition %q", transition)
				}

				resources := []model.Resource{service}
				if newWorkload != nil {
					resources = append(resources, *newWorkload)
				}
				snapshot := selectionSnapshot(t, resources)
				update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
					Key: oldWorkload.Key, Old: &oldWorkload, New: newWorkload,
				}})
				scope := model.ClientScope{
					Class:      client.class,
					Principal:  serviceAccountPrincipal("demo", "client"),
					SandboxUID: "uid-local",
				}
				watch := &watchState{
					started: true, names: sets.New(service.Aliases[0]),
					sent: map[string]string{
						service.XDSName:     service.Hash,
						oldWorkload.XDSName: oldWorkload.Hash,
					},
				}

				view := newDirtySubscriptionView(watch, model.AddressType, update)
				delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
					Scope: scope, TypeURL: model.AddressType, Subscription: view, Snapshot: snapshot, Update: update,
				})
				if err != nil {
					t.Fatal(err)
				}
				wantRemoved := []string{service.XDSName, oldWorkload.XDSName}
				if !slices.Equal(delta.Removed, wantRemoved) {
					t.Fatalf("membership loss removals = %v, want %v", delta.Removed, wantRemoved)
				}
				if len(delta.Resources) != 0 {
					t.Fatalf("membership loss resources = %v, want none", selectedNames(delta.Resources))
				}
			})
		}
	}
}

func TestGatewayWorkloadDirtyUsesResourceFamily(t *testing.T) {
	oldResource := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	newResource, err := model.NewResource(
		oldResource.Key, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid: "uid-a", Namespace: "demo", Node: "node-a", Name: "updated",
		}}}), nil, oldResource.Facts)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := selectionWorkload(t, "uid-b", "demo", "node-b", "", "")
	snapshot := selectionSnapshot(t, []model.Resource{newResource, unrelated})
	watch := &watchState{
		wildcard: true, started: true, names: sets.New[string](),
		sent: map[string]string{oldResource.XDSName: oldResource.Hash, unrelated.XDSName: unrelated.Hash},
	}
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldResource.Key, Old: &oldResource, New: &newResource,
	}})
	view := newDirtySubscriptionView(watch, model.AddressType, update)
	if names := view.SentNames(); !slices.Equal(names, []string{oldResource.XDSName}) {
		t.Fatalf("gateway dirty sent-state = %v, want only changed workload", names)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        gatewayScope(),
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-a"}) {
		t.Fatalf("dirty gateway resources = %v, want updated workload", names)
	}
}

func TestGatewayAuthorizationDirtyAllowsNonGlobalPolicy(t *testing.T) {
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
	snapshot := selectionSnapshot(t, []model.Resource{newResource, unrelated})
	watch := &watchState{
		wildcard: true, started: true, names: sets.New[string](),
		sent: map[string]string{oldResource.XDSName: oldResource.Hash, unrelated.XDSName: unrelated.Hash},
	}
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldResource.Key, Old: &oldResource, New: &newResource,
	}})
	view := newDirtySubscriptionView(watch, model.WorkloadAuthorizationType, update)
	if names := view.SentNames(); !slices.Equal(names, []string{oldResource.XDSName}) {
		t.Fatalf("gateway dirty sent-state = %v, want only changed authorization", names)
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
		t.Fatalf("dirty gateway authorizations = %v, want updated selector policy", names)
	}
}

func selectionSnapshot(t *testing.T, resources []model.Resource) model.ResourceSet {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func selectionWorkload(t *testing.T, uid, namespace, node, service, policyName string) model.Resource {
	t.Helper()
	facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
		SandboxUID: uid,
		NodeName:   node,
		Principal:  serviceAccountPrincipal(namespace, "default"),
	}}
	if service != "" {
		facts.Workload.ServiceKeys = []string{"demo/" + service}
	}
	authorizationPolicies := []string(nil)
	if policyName != "" {
		authorizationPolicies = []string{policyName}
		facts.Workload.AuthorizationRefs = []string{policyName}
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: uid}, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid: uid, Namespace: namespace, Node: node, AuthorizationPolicies: authorizationPolicies,
		}}}), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func projectedWorkloads(t *testing.T, scope model.ClientScope, snapshot model.ResourceSet, names []string) []model.Resource {
	t.Helper()
	subscription := SubscriptionView{wildcard: names == nil, names: append([]string(nil), names...)}
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope: scope, TypeURL: model.WorkloadType, Subscription: subscription, Snapshot: snapshot, Full: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return delta.Resources
}

func selectionService(t *testing.T, name string, aliases ...string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Service{Service: &workloadv1.Service{
			Name: name,
		}}}), aliases, model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: name}})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func selectionWithGatewayReference(t *testing.T, resource model.Resource, gatewayKey string) model.Resource {
	t.Helper()
	facts := resource.Facts
	workload := *facts.Workload
	workload.GatewayReferences = append(append([]string(nil), workload.GatewayReferences...), gatewayKey)
	facts.Workload = &workload
	updated, err := model.NewResource(resource.Key, resource.XDSName, resource.Value, resource.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func selectionOwnedByGateway(t *testing.T, resource model.Resource, gatewayKey string) model.Resource {
	t.Helper()
	facts := resource.Facts
	facts.GatewayOwner = gatewayKey
	updated, err := model.NewResource(resource.Key, resource.XDSName, resource.Value, resource.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func selectionAuthorization(
	t *testing.T,
	name string,
	scope model.AuthorizationScope,
	namespace string,
) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}, "",
		mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: name}), nil,
		model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{Scope: scope, Namespace: namespace}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func selectedNames(resources []model.Resource) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		names = append(names, resource.XDSName)
	}
	slices.Sort(names)
	return names
}
