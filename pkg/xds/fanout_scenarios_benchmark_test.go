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

const (
	scenarioResourceCount = 10_000
	scenarioNodeCount     = 100
)

type countingDeltaStream struct {
	ctx       context.Context
	responses int
	resources int
}

func (s *countingDeltaStream) Send(response *discoveryv3.DeltaDiscoveryResponse) error {
	s.responses++
	s.resources += len(response.GetResources()) + len(response.GetRemovedResources())
	return nil
}

func (*countingDeltaStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	return nil, io.EOF
}

func (s *countingDeltaStream) Context() context.Context   { return s.ctx }
func (*countingDeltaStream) SetHeader(metadata.MD) error  { return nil }
func (*countingDeltaStream) SendHeader(metadata.MD) error { return nil }
func (*countingDeltaStream) SetTrailer(metadata.MD)       {}
func (*countingDeltaStream) SendMsg(any) error            { return nil }
func (*countingDeltaStream) RecvMsg(any) error            { return io.EOF }

func TestSlowClientBurstConvergesFromFirstUnsentToFinalPublication(t *testing.T) {
	resource := func(payload string) model.Resource {
		result, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: "sandbox-a"}, "",
			&anypb.Any{TypeUrl: model.AddressType, Value: []byte(payload)}, nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: "sandbox-a",
				NodeName:   "node-a",
				Principal:  serviceAccountPrincipal("demo", "default"),
			}},
		)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	versions := []model.Resource{resource("zero"), resource("one"), resource("two"), resource("three")}
	initial, err := model.NewResourceSet(versions[:1])
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	ctx := t.Context()
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)

	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(ctx)
	apply := func(old, next model.Resource) Update {
		t.Helper()
		if _, err := store.Apply([]model.ResourceChange{{Key: next.Key, New: &next}}); err != nil {
			t.Fatal(err)
		}
		update := <-subscription.Updates()
		changes := update.ChangesForType(model.AddressType)
		if len(changes) != 1 || changes[0].Old == nil || changes[0].Old.Hash != old.Hash ||
			changes[0].New == nil || changes[0].New.Hash != next.Hash {
			t.Fatalf("publication change = %#v, want %q -> %q", changes, old.Hash, next.Hash)
		}
		return update
	}

	firstUpdate := apply(versions[0], versions[1])
	scheduler.Enqueue(connection, firstUpdate)
	first := scheduler.Next(context.Background())
	if first == nil {
		t.Fatal("first push was not scheduled")
	}

	scheduler.Enqueue(connection, apply(versions[1], versions[2]))
	scheduler.Enqueue(connection, apply(versions[2], versions[3]))
	scheduler.Done(first)
	final := scheduler.Next(context.Background())
	if final == nil {
		t.Fatal("coalesced final push was not scheduled")
	}
	defer scheduler.Done(final)

	before, found := final.Update.Before().Get(versions[1].Key)
	if !found || before.Hash != versions[1].Hash {
		t.Fatalf("coalesced Before = %#v, want first unsent version", before)
	}
	after, found := final.Update.After().Get(versions[3].Key)
	if !found || after.Hash != versions[3].Hash {
		t.Fatalf("coalesced After = %#v, want final version", after)
	}
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:   model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		TypeURL: model.AddressType, Subscription: SubscriptionView{wildcard: true},
		Snapshot: final.Update.After(), Update: final.Update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || delta.Resources[0].Hash != versions[3].Hash || len(delta.Removed) != 0 {
		t.Fatalf("coalesced delta resources=%#v removed=%v, want only final version", delta.Resources, delta.Removed)
	}
}

func BenchmarkRelationshipDirtyManyClients10000Resources(b *testing.B) {
	resources, updates := relationshipFanoutScenario(b)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("gateway-one-node-affected/clients-%d", clientCount), func(b *testing.B) {
			scopes, watches := distributedSharedClients(clientCount)
			expected := clientsOnNode(scopes, "node-050")
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendDirty(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
		b.Run(fmt.Sprintf("gateway-dedicated/clients-%d", clientCount), func(b *testing.B) {
			scopes := distributedDedicatedClients(clientCount)
			watches := wildcardWatches(clientCount)
			expected := 0
			for client := range scopes {
				if client%scenarioNodeCount == 50 {
					expected++
				}
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendDirty(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkAuthorizationDirtyManyClients10000Resources(b *testing.B) {
	resources, updates := authorizationFanoutScenario(b)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("exact-reference-one-node-affected/clients-%d", clientCount), func(b *testing.B) {
			scopes, watches := distributedSharedClients(clientCount)
			expected := clientsOnNode(scopes, "node-050")
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendDirty(stream, scope, log, model.WorkloadAuthorizationType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
		b.Run(fmt.Sprintf("exact-reference-dedicated/clients-%d", clientCount), func(b *testing.B) {
			scopes := distributedDedicatedClients(clientCount)
			watches := wildcardWatches(clientCount)
			expected := 0
			if clientCount > 50 {
				expected = 1
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendDirty(stream, scope, log, model.WorkloadAuthorizationType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkDirtyPushMixedClients10000Resources(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	updated, changed, err := initial.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		b.Fatalf("build mixed-client transition: changed=%v err=%v", changed, err)
	}
	updates := [2]Update{
		updateBetween(updated, initial, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}}),
		updateBetween(initial, updated, []model.ResourceChange{{Key: variants[1].Key, Old: &variants[0], New: &variants[1]}}),
	}
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("one-workload/clients-%d", clientCount), func(b *testing.B) {
			scopes := mixedClientScopes(clientCount)
			watches := wildcardWatches(clientCount)
			expected := affectedMixedClients(scopes, variants[0])
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendDirty(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkDirtyBatchManyClients10000Resources(b *testing.B) {
	resources, before, after, changes := dirtyBatchScenario(b, 1_000)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, dirtyCount := range []int{1, 100, 1_000} {
		for _, clientCount := range []int{1_000, 10_000} {
			if dirtyCount == 1_000 && clientCount == 10_000 {
				continue
			}
			b.Run(fmt.Sprintf("dirty-%d/clients-%d", dirtyCount, clientCount), func(b *testing.B) {
				scopes, watches := distributedSharedClients(clientCount)
				forward := updateBetween(before, after, changes[:dirtyCount])
				reverseChanges := make([]model.ResourceChange, dirtyCount)
				for index, change := range changes[:dirtyCount] {
					reverseChanges[index] = model.ResourceChange{Key: change.Key, Old: change.New, New: change.Old}
				}
				reverse := updateBetween(after, before, reverseChanges)
				updates := [2]Update{forward, reverse}
				expected := dirtyCount * clientCount / scenarioNodeCount
				b.ReportAllocs()
				b.ReportMetric(float64(clientCount), "clients/op")
				b.ReportMetric(float64(dirtyCount), "dirty-keys/op")
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					stream.responses = 0
					stream.resources = 0
					for client, scope := range scopes {
						if err := server.server.sendDirty(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
							b.Fatal(err)
						}
					}
					if stream.resources != expected {
						b.Fatalf("resources=%d, want %d", stream.resources, expected)
					}
				}
			})
		}
	}
}

func relationshipFanoutScenario(t testing.TB) ([]model.Resource, [2]Update) {
	t.Helper()
	resources := make([]model.Resource, 0, scenarioResourceCount+scenarioNodeCount)
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	for index := range scenarioResourceCount {
		node := fmt.Sprintf("node-%03d", index%scenarioNodeCount)
		name := fmt.Sprintf("sandbox-%06d", index)
		resources = append(resources, model.Resource{
			Key: model.ResourceKey{TypeURL: model.AddressType, Name: name}, XDSName: name,
			Value: value, Hash: name, Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				SandboxUID: name,
				NodeName:   node,
				Principal:  serviceAccountPrincipal("demo", "default"),
				GatewayReferences: []string{
					"gateway/" + node,
				},
			}},
		})
	}
	var variants [2]model.Resource
	for index := range scenarioNodeCount {
		node := fmt.Sprintf("node-%03d", index)
		name := "gateway-" + node
		resource := model.Resource{
			Key: model.ResourceKey{TypeURL: model.AddressType, Name: name}, XDSName: name,
			Value: value, Hash: name, Facts: model.ResourceFacts{
				Workload: &model.WorkloadResourceFacts{
					SandboxUID: name,
					Principal:  serviceAccountPrincipal("agentio-system", "gateway"),
				},
				GatewayOwner: "gateway/" + node,
			},
		}
		resources = append(resources, resource)
		if index == 50 {
			variants[0] = resource
			variants[1] = resource
			variants[0].Hash += "-old"
			variants[1].Hash += "-new"
			resources[len(resources)-1] = variants[0]
		}
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := before.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		t.Fatalf("build relationship transition: changed=%v err=%v", changed, err)
	}
	return resources, [2]Update{
		updateBetween(before, after, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[0], New: &variants[1]}}),
		updateBetween(after, before, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}}),
	}
}

func authorizationFanoutScenario(t testing.TB) ([]model.Resource, [2]Update) {
	t.Helper()
	const targetPolicy = "demo/policy-target"
	resources := make([]model.Resource, 0, scenarioResourceCount*2)
	for index := range scenarioResourceCount {
		node := fmt.Sprintf("node-%03d", index%scenarioNodeCount)
		name := fmt.Sprintf("sandbox-%06d", index)
		policies := []string(nil)
		if index == 50 {
			policies = []string{targetPolicy}
		}
		facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			SandboxUID:        name,
			NodeName:          node,
			Principal:         serviceAccountPrincipal("demo", "default"),
			AuthorizationRefs: policies,
		}}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
			mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
				Uid: name, Namespace: "demo", Node: node, AuthorizationPolicies: policies,
			}}}), nil,
			facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	value := &anypb.Any{TypeUrl: model.WorkloadAuthorizationType, Value: []byte("authorization")}
	var variants [2]model.Resource
	for index := range scenarioResourceCount {
		name := fmt.Sprintf("demo/policy-%06d", index)
		if index == 5_000 {
			name = targetPolicy
		}
		resource := model.Resource{
			Key: model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}, XDSName: name,
			Value: value, Hash: name + "-old",
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope: model.AuthorizationScopeWorkload,
			}},
		}
		resources = append(resources, resource)
		if name == targetPolicy {
			variants[0] = resource
			variants[1] = resource
			variants[1].Hash = name + "-new"
		}
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := before.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		t.Fatalf("build Authorization transition: changed=%v err=%v", changed, err)
	}
	return resources, [2]Update{
		updateBetween(before, after, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[0], New: &variants[1]}}),
		updateBetween(after, before, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}}),
	}
}

func dirtyBatchScenario(t testing.TB, dirtyCount int) (
	[]model.Resource, model.ResourceSet, model.ResourceSet, []model.ResourceChange,
) {
	t.Helper()
	resources, _ := fanoutBenchmarkResources(t)
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	changes := make([]model.ResourceChange, 0, dirtyCount)
	for index := range dirtyCount {
		old := resources[index]
		updated := old
		updated.Hash += "-new"
		changes = append(changes, model.ResourceChange{Key: old.Key, Old: &old, New: &updated})
	}
	after, changed, err := before.Apply(changes)
	if err != nil || !changed {
		t.Fatalf("build dirty batch: changed=%v err=%v", changed, err)
	}
	return resources, before, after, changes
}

func distributedSharedClients(clientCount int) ([]model.ClientScope, []*watchState) {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		scopes[client] = model.ClientScope{
			Class: model.ClientSharedZTunnel, NodeName: fmt.Sprintf("node-%03d", client%scenarioNodeCount),
		}
	}
	return scopes, wildcardWatches(clientCount)
}

func distributedDedicatedClients(clientCount int) []model.ClientScope {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		scopes[client] = model.ClientScope{
			Class: model.ClientDedicatedZTunnel, SandboxUID: fmt.Sprintf("sandbox-%06d", client),
		}
	}
	return scopes
}

func mixedClientScopes(clientCount int) []model.ClientScope {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		if client%2 == 0 {
			scopes[client] = model.ClientScope{
				Class: model.ClientSharedZTunnel, NodeName: fmt.Sprintf("node-%03d", (client/2)%scenarioNodeCount),
			}
			continue
		}
		index := client / 2
		if client == 1 {
			index = fanoutTargetIndex
		} else if index == fanoutTargetIndex {
			index++
		}
		scopes[client] = model.ClientScope{
			Class: model.ClientDedicatedZTunnel, SandboxUID: fmt.Sprintf("sandbox-%06d", index),
		}
	}
	return scopes
}

func wildcardWatches(clientCount int) []*watchState {
	watches := make([]*watchState, clientCount)
	for client := range watches {
		watches[client] = &watchState{
			wildcard: true, started: true, names: sets.New[string](), sent: make(map[string]string),
		}
	}
	return watches
}

func clientsOnNode(scopes []model.ClientScope, node string) int {
	result := 0
	for _, scope := range scopes {
		if scope.Class == model.ClientSharedZTunnel && scope.NodeName == node {
			result++
		}
	}
	return result
}

func affectedMixedClients(scopes []model.ClientScope, resource model.Resource) int {
	result := 0
	for _, scope := range scopes {
		if workloadMatchesScope(scope, resource) {
			result++
		}
	}
	return result
}
