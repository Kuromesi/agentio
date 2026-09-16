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
	"reflect"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func sharedTrafficResource(t *testing.T, name string, action securityv1.TrafficPolicy_Action) model.Resource {
	t.Helper()
	body, err := anypb.New(&securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{Rules: []*securityv1.TrafficPolicy_Rule{{Action: action, Match: &securityv1.TrafficPolicy_Match{}}}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.NewResource(model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name}, "", body, nil, model.ResourceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sandboxWithTrafficRefs(t *testing.T, uid, workload string, names ...string) model.Resource {
	t.Helper()
	body, err := anypb.New(&sandboxv1.Sandbox{Uid: uid, Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: workload}, PolicyRefs: map[string]*sandboxv1.PolicyReference{model.TrafficPolicyType: {ResourceNames: names}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.NewResource(model.ResourceKey{TypeURL: model.SandboxType, Name: uid}, "", body, nil, model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: workload, TrafficPolicyRefs: names}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSharedTrafficPolicyWildcardUpdatesAndScope(t *testing.T) {
	worker := workerResource(t, "pod-1")
	name := "namespaces/demo/trafficPolicies/shared"
	shared := sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	private := sharedTrafficResource(t, "namespaces/other/trafficPolicies/private", securityv1.TrafficPolicy_DENY)
	outside := sandboxWithTrafficRefs(t, "outside", "other-worker", private.Key.Name)
	server := newTestServer(t, workerScope(worker), []model.Resource{worker, shared, private, outside}, nil)
	stream := newFakeStream(t.Context(), 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.TrafficPolicyType))
	first := stream.awaitResponses(t, model.TrafficPolicyType, 1)[0]
	if len(first.Resources) != 0 {
		t.Fatalf("warm pool received unrelated policies: %v", first)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: first.Nonce})
	a := sandboxWithTrafficRefs(t, "a", "worker", name)
	b := sandboxWithTrafficRefs(t, "b", "worker", name)
	server.resources.publish(selectionSnapshot(t, []model.Resource{worker, shared, private, outside, a, b}))
	response := stream.awaitResponses(t, model.TrafficPolicyType, 2)[1]
	if !reflect.DeepEqual(resourceNames(response), []string{name}) {
		t.Fatalf("shared policy should be delivered once: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
	changed := sharedTrafficResource(t, name, securityv1.TrafficPolicy_DENY)
	server.resources.publish(selectionSnapshot(t, []model.Resource{worker, changed, private, outside, a, b}))
	response = stream.awaitResponses(t, model.TrafficPolicyType, 3)[2]
	if len(response.Resources) != 1 || response.Resources[0].Version != changed.Hash {
		t.Fatalf("body update missing: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce, ResourceNamesSubscribe: []string{private.Key.Name}})
	response = stream.awaitResponses(t, model.TrafficPolicyType, 4)[3]
	if len(response.Resources) != 0 || !reflect.DeepEqual(response.RemovedResources, []string{private.Key.Name}) {
		t.Fatalf("named subscribe widened scope: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                model.TrafficPolicyType,
		ResponseNonce:          response.Nonce,
		ResourceNamesSubscribe: []string{name, name},
	})
	response = stream.awaitResponses(t, model.TrafficPolicyType, 5)[4]
	if !reflect.DeepEqual(resourceNames(response), []string{name}) || len(response.RemovedResources) != 0 {
		t.Fatalf("repeated subscribe must resend cached policy once: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
	// The same Pod name with another source UID is no longer this client's host.
	replacement := workerResource(t, "pod-2")
	server.resources.publish(selectionSnapshot(t, []model.Resource{replacement, changed, private, outside, a, b}))
	response = stream.awaitResponses(t, model.TrafficPolicyType, 6)[5]
	if len(response.Resources) != 0 || !reflect.DeepEqual(response.RemovedResources, []string{name}) {
		t.Fatalf("lost scope did not withdraw policy: %v", response)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTrafficPolicyReferencesAuthorizeOnlyTheirResources(t *testing.T) {
	worker := workerResource(t, "pod-1")
	p := sharedTrafficResource(t, "trafficPolicies/global", securityv1.TrafficPolicy_DENY)
	sandbox := sandboxWithTrafficRefs(t, "a", "worker", p.Key.Name)
	generator := TrafficPolicyGenerator{}
	for _, tc := range []struct {
		name      string
		resources []model.Resource
		want      int
	}{
		{"unreferenced", []model.Resource{worker, p}, 0},
		{"missing body", []model.Resource{worker, sandbox}, 0},
		{"resolved", []model.Resource{worker, sandbox, p}, 1},
		{"removed reference", []model.Resource{worker, sandboxWithTrafficRefs(t, "a", "worker"), p}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta, err := generator.Generate(t.Context(), GenerationRequest{Scope: workerScope(worker), TypeURL: model.TrafficPolicyType, Snapshot: selectionSnapshot(t, tc.resources), Full: true, Subscription: SubscriptionView{wildcard: true, sent: map[string]string{p.Key.Name: "old"}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != tc.want {
				t.Fatalf("resources: %v", delta.Resources)
			}
			if tc.want == 0 && !reflect.DeepEqual(delta.Removed, []string{p.Key.Name}) {
				t.Fatalf("removal: %v", delta.Removed)
			}
		})
	}
}

func TestSandboxTrafficPolicyReferenceUpdates(t *testing.T) {
	worker := workerResource(t, "pod-1")
	name := "trafficPolicies/global"
	body := sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	sandbox := sandboxWithTrafficRefs(t, "sandbox", "worker", name)
	for _, scope := range []model.ClientScope{workerScope(worker), gatewayScope()} {
		server := newTestServer(t, scope, []model.Resource{worker, body}, nil)
		stream := newFakeStream(t.Context(), 8)
		done := server.start(stream)
		stream.send(nodeRequest(model.TrafficPolicyType))
		response := stream.awaitResponses(t, model.TrafficPolicyType, 1)[0]
		if len(response.Resources) != 0 {
			t.Fatal("unreferenced policy was exposed")
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		server.resources.publish(selectionSnapshot(t, []model.Resource{worker, sandbox, body}))
		response = stream.awaitResponses(t, model.TrafficPolicyType, 2)[1]
		if !reflect.DeepEqual(resourceNames(response), []string{name}) {
			t.Fatalf("Sandbox reference did not grant visibility: %v", response)
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		body = sharedTrafficResource(t, name, securityv1.TrafficPolicy_DENY)
		server.resources.publish(selectionSnapshot(t, []model.Resource{worker, sandbox, body}))
		response = stream.awaitResponses(t, model.TrafficPolicyType, 3)[2]
		if len(response.Resources) != 1 || response.Resources[0].Version != body.Hash {
			t.Fatalf("Sandbox policy body update missing: %v", response)
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		server.resources.publish(selectionSnapshot(t, []model.Resource{worker, sandboxWithTrafficRefs(t, "sandbox", "worker"), body}))
		response = stream.awaitResponses(t, model.TrafficPolicyType, 4)[3]
		if !reflect.DeepEqual(response.RemovedResources, []string{name}) {
			t.Fatalf("removed Sandbox reference retained visibility: %v", response)
		}
		if err := server.finish(t, stream, done); err != nil {
			t.Fatal(err)
		}
		body = sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	}
}
