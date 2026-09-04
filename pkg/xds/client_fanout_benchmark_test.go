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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

const fanoutResourceCount = 10_000
const fanoutTargetIndex = 5_050

func BenchmarkDirtyPushManyClients10000Resources(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("dedicated-one-affected/clients-%d", clientCount), func(b *testing.B) {
			scopes := make([]model.ClientScope, clientCount)
			for client := range scopes {
				index := fanoutTargetIndex
				if client > 0 {
					index = client - 1
					if index >= fanoutTargetIndex {
						index++
					}
				}
				scopes[client] = model.ClientScope{
					Class:      model.ClientDedicatedZTunnel,
					SandboxUID: fmt.Sprintf("sandbox-%06d", index),
				}
			}
			benchmarkDirtyClientFanout(b, resources, variants, scopes)
		})
		b.Run(fmt.Sprintf("shared-all-affected/clients-%d", clientCount), func(b *testing.B) {
			scopes := make([]model.ClientScope, clientCount)
			for client := range scopes {
				scopes[client] = model.ClientScope{
					Class:    model.ClientSharedZTunnel,
					NodeName: "node-050",
				}
			}
			benchmarkDirtyClientFanout(b, resources, variants, scopes)
		})
	}
}

func BenchmarkStorePublishManyClients10000Resources(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("clients-%d", clientCount), func(b *testing.B) {
			ctx := b.Context()
			store := NewStore(initial)
			subscriptions := make([]ResourceSubscription, clientCount)
			for client := range subscriptions {
				subscriptions[client] = store.Subscribe(ctx)
				subscriptions[client].Watch(model.AddressType)
			}
			next := 1
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for range b.N {
				resource := variants[next]
				if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
					b.Fatal(err)
				}
				for _, subscription := range subscriptions {
					<-subscription.Updates()
				}
				next ^= 1
			}
		})
	}
}

func BenchmarkPushSchedulerManyClients(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	store := NewStore(initial)
	ctx := b.Context()
	updates := store.subscribeAll(ctx)
	resource := variants[1]
	if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
		b.Fatal(err)
	}
	update := <-updates

	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("clients-%d", clientCount), func(b *testing.B) {
			scheduler := NewPushScheduler(clientCount)
			defer scheduler.Close()
			connections := make([]*pushConnection, clientCount)
			for client := range connections {
				connections[client] = newPushConnection(context.Background())
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for range b.N {
				for _, connection := range connections {
					scheduler.Enqueue(connection, update)
				}
				for range connections {
					push := scheduler.Next(context.Background())
					if push == nil {
						b.Fatal("scheduler closed before delivering all clients")
					}
					scheduler.Done(push)
				}
			}
		})
	}
}

func benchmarkDirtyClientFanout(
	b *testing.B,
	resources []model.Resource,
	variants [2]model.Resource,
	scopes []model.ClientScope,
) {
	b.Helper()
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewStore(initial)
	updates := store.subscribeAll(ctx)
	testServer := newTestServer(b, ztunnelScope(), resources, nil)
	testServer.server.resources = store
	stream := discardDeltaStream{ctx: context.Background()}
	watches := make([]*watchState, len(scopes))
	for client := range watches {
		watches[client] = &watchState{
			wildcard: true,
			started:  true,
			names:    sets.New[string](),
			sent:     make(map[string]string),
		}
	}

	next := 1
	b.ReportAllocs()
	b.ReportMetric(float64(len(scopes)), "clients/op")
	b.ResetTimer()
	for range b.N {
		resource := variants[next]
		if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
			b.Fatal(err)
		}
		update := <-updates
		for client, scope := range scopes {
			if err := testServer.server.sendDirty(stream, scope, log, model.AddressType, watches[client], update); err != nil {
				b.Fatal(err)
			}
		}
		next ^= 1
	}
}

func fanoutBenchmarkResources(t testing.TB) ([]model.Resource, [2]model.Resource) {
	t.Helper()
	resources := make([]model.Resource, 0, fanoutResourceCount)
	var variants [2]model.Resource
	for index := range fanoutResourceCount {
		name := fmt.Sprintf("sandbox-%06d", index)
		facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			SandboxUID: name,
			NodeName:   fmt.Sprintf("node-%03d", index%100),
			Principal:  serviceAccountPrincipal("demo", "default"),
		}}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name},
			"",
			&anypb.Any{TypeUrl: model.AddressType, Value: []byte("old")},
			nil,
			facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
		if index == fanoutTargetIndex {
			variants[0] = resource
			variants[1], err = model.NewResource(
				resource.Key,
				"",
				&anypb.Any{TypeUrl: model.AddressType, Value: []byte("new")},
				nil,
				facts,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return resources, variants
}
