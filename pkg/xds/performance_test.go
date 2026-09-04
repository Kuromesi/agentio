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
	"io"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

type discardDeltaStream struct{ ctx context.Context }

func (d discardDeltaStream) Send(*discoveryv3.DeltaDiscoveryResponse) error { return nil }
func (d discardDeltaStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	return nil, io.EOF
}
func (d discardDeltaStream) Context() context.Context   { return d.ctx }
func (discardDeltaStream) SetHeader(metadata.MD) error  { return nil }
func (discardDeltaStream) SendHeader(metadata.MD) error { return nil }
func (discardDeltaStream) SetTrailer(metadata.MD)       {}
func (discardDeltaStream) SendMsg(any) error            { return nil }
func (discardDeltaStream) RecvMsg(any) error            { return io.EOF }

func BenchmarkDeltaPushSingleKeyInLargeSnapshot(b *testing.B) {
	const resourceCount = 100_000
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	resources := make([]model.Resource, 0, resourceCount)
	for i := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%06d", i)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name,
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: name,
				NodeName:   "node-a",
				Principal:  serviceAccountPrincipal("default", "default"),
			}},
		})
	}
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	testServer := newTestServer(b, scope, resources, nil)
	stream := discardDeltaStream{ctx: context.Background()}

	b.Run("dirty-key", func(b *testing.B) {
		key := resources[resourceCount/2].Key
		variants := [2]model.Resource{resources[resourceCount/2], resources[resourceCount/2]}
		variants[0].Hash += "-a"
		variants[1].Hash += "-b"
		base, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		var snapshots [2]model.ResourceSet
		for variant := range variants {
			snapshot, changed, err := base.Apply([]model.ResourceChange{{Key: key, New: &variants[variant]}})
			if err != nil || !changed {
				b.Fatalf("build variant %d: changed=%v err=%v", variant, changed, err)
			}
			snapshots[variant] = snapshot
		}
		updates := [2]Update{
			updateBetween(snapshots[1], snapshots[0], []model.ResourceChange{{
				Key: key, Old: &variants[1], New: &variants[0],
			}}),
			updateBetween(snapshots[0], snapshots[1], []model.ResourceChange{{
				Key: key, Old: &variants[0], New: &variants[1],
			}}),
		}
		sent := make(map[string]string, len(resources))
		for _, resource := range resources {
			sent[resource.XDSName] = resource.Hash
		}
		watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			update := updates[i%2]
			if err := testServer.server.sendDirty(stream, testServer.scope, log, model.AddressType, watch, update); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("full-type-scan", func(b *testing.B) {
		sent := make(map[string]string, len(resources))
		for _, resource := range resources {
			sent[resource.XDSName] = resource.Hash
		}
		watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := testServer.server.sendDiff(stream, testServer.scope, log, model.AddressType, watch, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkWildcardWDSConnectionState5000(b *testing.B) {
	const resourceCount = 5_000
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%05d", index)
		resources = append(resources, addressResource(b, name, name))
	}
	scope := ztunnelScope()
	server := newTestServer(b, scope, resources, nil)
	stream := discardDeltaStream{ctx: context.Background()}

	b.ReportAllocs()
	for b.Loop() {
		watch := &watchState{
			wildcard: true,
			started:  true,
			names:    sets.New[string](),
			sent:     map[string]string{},
		}
		if err := server.server.sendDiff(stream, scope, log, model.AddressType, watch, true); err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(len(watch.sent)), "sent-hashes")
	}
}

// Fanout guard exercising the real dirty path; sized to catch per-client full scans.
func BenchmarkDirtyPushManyKeysManyClients(b *testing.B) {
	const keyCount, clientCount = 100, 25
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	variants := [2][]model.Resource{
		make([]model.Resource, 0, keyCount),
		make([]model.Resource, 0, keyCount),
	}
	changes := [2][]model.ResourceChange{
		make([]model.ResourceChange, 0, keyCount),
		make([]model.ResourceChange, 0, keyCount),
	}
	for index := range keyCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%03d", index)
		for variant := range variants {
			variants[variant] = append(variants[variant], model.Resource{
				Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
				XDSName: name,
				Value:   value,
				Hash:    fmt.Sprintf("%s-%d", name, variant),
				Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
					SandboxUID: name,
					NodeName:   "node-a",
					Principal:  serviceAccountPrincipal("default", "default"),
				}},
			})
		}
		changes[0] = append(changes[0], model.ResourceChange{
			Key: variants[0][index].Key, Old: &variants[1][index], New: &variants[0][index],
		})
		changes[1] = append(changes[1], model.ResourceChange{
			Key: variants[0][index].Key, Old: &variants[0][index], New: &variants[1][index],
		})
	}
	var snapshots [2]model.ResourceSet
	for variant := range variants {
		var err error
		snapshots[variant], err = model.NewResourceSet(variants[variant])
		if err != nil {
			b.Fatal(err)
		}
	}
	updates := [2]Update{
		updateBetween(snapshots[1], snapshots[0], changes[0]),
		updateBetween(snapshots[0], snapshots[1], changes[1]),
	}
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	testServer := newTestServer(b, scope, variants[0], nil)
	stream := discardDeltaStream{ctx: context.Background()}
	watches := make([]*watchState, clientCount)
	for client := range watches {
		sent := make(map[string]string, keyCount)
		for _, resource := range variants[0] {
			sent[resource.XDSName] = resource.Hash
		}
		watches[client] = &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
	}

	b.ReportAllocs()

	for iteration := 0; b.Loop(); iteration++ {
		update := updates[(iteration+1)%2]
		for _, watch := range watches {
			if err := testServer.server.sendDirty(stream, scope, log, model.AddressType, watch, update); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkSandboxReferencedGatewayDirty5000(b *testing.B) {
	const unrelatedCount = 5_000
	value := func(payload string) *anypb.Any {
		return &anypb.Any{TypeUrl: model.AddressType, Value: []byte(payload)}
	}
	resource := func(name, payload string, facts model.ResourceFacts) model.Resource {
		result, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "", value(payload), nil, facts)
		if err != nil {
			b.Fatal(err)
		}
		return result
	}
	resources := make([]model.Resource, 0, unrelatedCount+3)
	for index := range unrelatedCount {
		name := fmt.Sprintf("other-%05d", index)
		resources = append(resources, resource(fmt.Sprintf("unrelated-%05d", index), "unrelated",
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: name,
				Principal:  serviceAccountPrincipal("other", "default"),
			}}))
	}
	resources = append(resources, resource("uid-a", "sandbox",
		model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			SandboxUID:        "uid-a",
			Principal:         serviceAccountPrincipal("demo", "default"),
			GatewayReferences: []string{"agentio-system/egress-a"},
		}}))
	oldGateway := resource("gateway-a", "old",
		model.ResourceFacts{
			Workload:     &model.WorkloadResourceFacts{SandboxUID: "gateway-a", Principal: serviceAccountPrincipal("agentio-system", "gateway")},
			GatewayOwner: "agentio-system/egress-a",
		})
	newGateway := resource("gateway-a", "new",
		model.ResourceFacts{
			Workload:     &model.WorkloadResourceFacts{SandboxUID: "gateway-a", Principal: serviceAccountPrincipal("agentio-system", "gateway")},
			GatewayOwner: "agentio-system/egress-a",
		})
	oldResources := append(append([]model.Resource(nil), resources...), oldGateway)
	newResources := append(append([]model.Resource(nil), resources...), newGateway)
	oldSnapshot, err := model.NewResourceSet(oldResources)
	if err != nil {
		b.Fatal(err)
	}
	newSnapshot, err := model.NewResourceSet(newResources)
	if err != nil {
		b.Fatal(err)
	}
	request := GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-a"},
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     newSnapshot,
		Update: updateBetween(oldSnapshot, newSnapshot, []model.ResourceChange{{
			Key: newGateway.Key, Old: &oldGateway, New: &newGateway,
		}}),
	}
	if got := generateWDSDirty(request, false); len(got.Resources) != 1 || got.Resources[0].XDSName != "gateway-a" {
		b.Fatalf("representative delta = %+v", got)
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = generateWDSDirty(request, false)
	}
}

func TestDirtyPublicationTransitionAtTenThousandResources(t *testing.T) {
	_, after, update, target := scaleWorkloadTransition(t, 10_000)
	for _, test := range []struct {
		name  string
		scope model.ClientScope
	}{
		{name: "dedicated", scope: model.ClientScope{
			Class: model.ClientDedicatedZTunnel, SandboxUID: target.Key.Name,
		}},
		{name: "node", scope: model.ClientScope{
			Class: model.ClientSharedZTunnel, NodeName: "node-050",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
				Scope: test.scope, TypeURL: model.AddressType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     after, Update: update,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := selectedNames(delta.Resources); len(got) != 1 || got[0] != target.XDSName {
				t.Fatalf("dirty resources = %v, want only %q", got, target.XDSName)
			}
			if len(delta.Removed) != 0 {
				t.Fatalf("dirty removals = %v, want none", delta.Removed)
			}
		})
	}
}

func BenchmarkDirtyPublicationTransition10000(b *testing.B) {
	_, after, update, target := scaleWorkloadTransition(b, 10_000)
	for _, benchmark := range []struct {
		name  string
		scope model.ClientScope
	}{
		{name: "dedicated", scope: model.ClientScope{
			Class: model.ClientDedicatedZTunnel, SandboxUID: target.Key.Name,
		}},
		{name: "node-100-workloads", scope: model.ClientScope{
			Class: model.ClientSharedZTunnel, NodeName: "node-050",
		}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			request := GenerationRequest{
				Scope: benchmark.scope, TypeURL: model.AddressType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     after, Update: update,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				delta, err := (WorkloadGenerator{}).Generate(context.Background(), request)
				if err != nil || len(delta.Resources) != 1 {
					b.Fatalf("Generate() resources=%d err=%v", len(delta.Resources), err)
				}
			}
		})
	}
}

func BenchmarkAuthorizationDirty10000(b *testing.B) {
	const authorizationCount = 10_000
	const workloadCount = 100
	const targetName = "demo/policy-005000"
	workload := func(uid, node string, policies []string) model.Resource {
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: uid}, "",
			mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
				Uid: uid, Namespace: "demo", Node: node, AuthorizationPolicies: policies,
			}}}), nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID:        uid,
				NodeName:          node,
				Principal:         serviceAccountPrincipal("demo", "default"),
				AuthorizationRefs: policies,
			}},
		)
		if err != nil {
			b.Fatal(err)
		}
		return resource
	}
	resources := make([]model.Resource, 0, authorizationCount+workloadCount+1)
	resources = append(resources, workload("uid-000", "node-a", []string{targetName}))
	for index := 1; index < workloadCount; index++ {
		resources = append(resources, workload(fmt.Sprintf("uid-%03d", index), "node-a", nil))
	}
	oldRemote := workload("uid-remote", "node-z", nil)
	resources = append(resources, oldRemote)
	value := &anypb.Any{TypeUrl: model.WorkloadAuthorizationType, Value: []byte("authorization")}
	for index := range authorizationCount {
		name := fmt.Sprintf("demo/policy-%06d", index)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name},
			XDSName: name, Value: value, Hash: name + "-old",
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope: model.AuthorizationScopeWorkload,
			}},
		})
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	targetKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: targetName}
	oldTarget, found := before.Get(targetKey)
	if !found {
		b.Fatalf("target Authorization %q not found", targetName)
	}
	newTarget := oldTarget
	newTarget.Hash = targetName + "-new"
	afterPolicy, changed, err := before.Apply([]model.ResourceChange{{Key: targetKey, New: &newTarget}})
	if err != nil || !changed {
		b.Fatalf("build Authorization transition: changed=%v err=%v", changed, err)
	}
	policyUpdate := updateBetween(before, afterPolicy, []model.ResourceChange{{
		Key: targetKey, Old: &oldTarget, New: &newTarget,
	}})

	newRemote := oldRemote
	newRemote.Hash += "-new"
	afterChurn, changed, err := before.Apply([]model.ResourceChange{{Key: oldRemote.Key, New: &newRemote}})
	if err != nil || !changed {
		b.Fatalf("build Address churn transition: changed=%v err=%v", changed, err)
	}
	churnUpdate := updateBetween(before, afterChurn, []model.ResourceChange{{
		Key: oldRemote.Key, Old: &oldRemote, New: &newRemote,
	}})

	dedicated := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-000"}
	node := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	for _, benchmark := range []struct {
		name          string
		scope         model.ClientScope
		snapshot      model.ResourceSet
		update        Update
		wantResources int
	}{
		{name: "policy-change/dedicated", scope: dedicated,
			snapshot: afterPolicy, update: policyUpdate, wantResources: 1},
		{name: "policy-change/node-100-workloads", scope: node,
			snapshot: afterPolicy, update: policyUpdate, wantResources: 1},
		{name: "unrelated-address-churn/node-100-workloads", scope: node,
			snapshot: afterChurn, update: churnUpdate, wantResources: 0},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			request := GenerationRequest{
				Scope:        benchmark.scope,
				TypeURL:      model.WorkloadAuthorizationType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     benchmark.snapshot,
				Update:       benchmark.update,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				delta, err := (AuthorizationGenerator{}).Generate(context.Background(), request)
				if err != nil || len(delta.Resources) != benchmark.wantResources {
					b.Fatalf("Generate() resources=%d err=%v, want %d resources",
						len(delta.Resources), err, benchmark.wantResources)
				}
			}
		})
	}
}

func scaleWorkloadTransition(t testing.TB, resourceCount int) (
	model.ResourceSet, model.ResourceSet, Update, model.Resource,
) {
	t.Helper()
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("sandbox-%06d", index)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name, Value: value, Hash: name + "-old",
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: name,
				NodeName:   fmt.Sprintf("node-%03d", index%100),
				Principal:  serviceAccountPrincipal("demo", "default"),
			}},
		})
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	targetKey := model.ResourceKey{TypeURL: model.AddressType, Name: "sandbox-005050"}
	oldTarget, found := before.Get(targetKey)
	if !found {
		t.Fatalf("target Workload %q not found", targetKey.Name)
	}
	newTarget := oldTarget
	newTarget.Hash = targetKey.Name + "-new"
	after, changed, err := before.Apply([]model.ResourceChange{{Key: targetKey, New: &newTarget}})
	if err != nil || !changed {
		t.Fatalf("build Workload transition: changed=%v err=%v", changed, err)
	}
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: targetKey, Old: &oldTarget, New: &newTarget,
	}})
	return before, after, update, newTarget
}
