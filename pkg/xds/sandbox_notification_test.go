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
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func TestDedicatedAddressNotificationsExcludeOtherWorkloads(t *testing.T) {
	worker := workerResource(t, "pod-1")
	server := newTestServer(t, workerScope(worker), []model.Resource{worker}, nil)
	resources := xdsstore.New(server.resources.Snapshot())
	server.server.resources = resources
	subscription := resources.Subscribe(t.Context())
	stream := newFakeStream(t.Context(), 1)
	watches := map[string]*watchState{}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		watches,
		subscription,
		nodeRequest(model.AddressType, "*"),
	); err != nil {
		t.Fatal(err)
	}
	other := selectionWorkload(t, "other", "workers", "node-a", "", "")
	resources.Replace(selectionSnapshot(t, []model.Resource{worker, other}))
	select {
	case <-subscription.Updates():
		t.Fatal("unrelated Workload woke dedicated Address subscriber")
	default:
	}
	resources.Replace(selectionSnapshot(t, []model.Resource{other}))
	select {
	case update := <-subscription.Updates():
		if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("own Workload removal missed notification")
	}
	responses := stream.sent()
	if len(responses) != 2 || len(responses[1].RemovedResources) != 1 ||
		responses[1].RemovedResources[0] != worker.XDSName {
		t.Fatalf("own Workload was not withdrawn: %v", responses)
	}
}

// An unrelated Sandbox must not occupy a connection's push mailbox. Filtering
// only in the generator leaves the fanout and merge costs on every connection.
func TestSandboxNotificationsFollowDemand(t *testing.T) {
	server := newTestServer(t, gatewayScope(), nil, nil)
	resources := xdsstore.New(server.resources.Snapshot())
	server.server.resources = resources
	subscription := resources.Subscribe(t.Context())
	watches := map[string]*watchState{}
	stream := newFakeStream(t.Context(), 1)
	request := func(subscribed, unsubscribed []string) {
		t.Helper()
		if err := server.server.handleRequest(
			stream,
			server.scope,
			log,
			watches,
			subscription,
			&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                  model.SandboxType,
				ResourceNamesSubscribe:   subscribed,
				ResourceNamesUnsubscribe: unsubscribed,
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	request([]string{"wanted"}, nil)
	other := sandboxResource(t, "other")
	resources.Replace(selectionSnapshot(t, []model.Resource{other}))
	select {
	case <-subscription.Updates():
		t.Fatal("unrelated Sandbox woke named subscriber")
	default:
	}
	wanted := sandboxResource(t, "wanted")
	resources.Replace(selectionSnapshot(t, []model.Resource{wanted}))
	select {
	case update := <-subscription.Updates():
		candidates := update.Candidates(model.SandboxType)
		if len(candidates) != 1 || candidates[0].Key.Name != "wanted" {
			t.Fatalf("unrelated candidates retained in mailbox: %+v", candidates)
		}
		if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("demand for absent Sandbox missed its creation")
	}
	request(nil, []string{"wanted"})
	resources.Replace(selectionSnapshot(t, nil))
	select {
	case <-subscription.Updates():
		t.Fatal("unsubscribed Sandbox woke subscriber")
	default:
	}
	request([]string{"wanted"}, nil)
	resources.Replace(selectionSnapshot(t, []model.Resource{wanted}))
	select {
	case <-subscription.Updates():
	default:
		t.Fatal("resubscribed Sandbox missed its creation")
	}
}

func TestSandboxNotificationWithdrawsLostBinding(t *testing.T) {
	for _, migration := range []bool{false, true} {
		t.Run(map[bool]string{false: "workload deletion", true: "attester migration"}[migration], func(t *testing.T) {
			worker := workerResource(t, "pod-1")
			sandbox := sandboxResourceWithAttester(t, "actor", "worker")
			server := newTestServer(t, workerScope(worker), []model.Resource{worker, sandbox}, nil)
			resources := xdsstore.New(server.resources.Snapshot())
			server.server.resources = resources
			subscription := resources.Subscribe(t.Context())
			stream := newFakeStream(t.Context(), 1)
			watches := map[string]*watchState{}
			if err := server.server.handleRequest(
				stream,
				server.scope,
				log,
				watches,
				subscription,
				nodeRequest(model.SandboxType, "actor"),
			); err != nil {
				t.Fatal(err)
			}
			if len(stream.sent()[0].Resources) != 1 {
				t.Fatal("initial Sandbox not delivered")
			}
			next := []model.Resource{sandbox}
			if migration {
				next = []model.Resource{worker, sandboxResourceWithAttester(t, "actor", "another-worker")}
			}
			resources.Replace(selectionSnapshot(t, next))
			select {
			case update := <-subscription.Updates():
				if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("lost binding did not notify the named subscriber")
			}
			responses := stream.sent()
			if len(responses) != 2 || len(responses[1].RemovedResources) != 1 ||
				responses[1].RemovedResources[0] != "actor" {
				t.Fatalf("bound Sandbox was not withdrawn: %v", responses)
			}
		})
	}
}

func TestSandboxNotificationRestoresCachedInterests(t *testing.T) {
	a, b := sandboxResource(t, "a"), sandboxResource(t, "b")
	server := newTestServer(t, gatewayScope(), []model.Resource{a, b}, nil)
	resources := xdsstore.New(server.resources.Snapshot())
	server.server.resources = resources
	subscription := resources.Subscribe(t.Context())
	stream := newFakeStream(t.Context(), 1)
	watches := map[string]*watchState{}
	request := nodeRequest(model.SandboxType, "a")
	request.InitialResourceVersions = map[string]string{"b": b.Hash}
	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription, request); err != nil {
		t.Fatal(err)
	}
	resources.Replace(selectionSnapshot(t, []model.Resource{a}))
	select {
	case update := <-subscription.Updates():
		if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("initial_resource_versions did not restore notification interest")
	}
	responses := stream.sent()
	if len(responses) != 2 || len(responses[1].RemovedResources) != 1 || responses[1].RemovedResources[0] != "b" {
		t.Fatalf("cached Sandbox was not withdrawn: %v", responses)
	}
}
