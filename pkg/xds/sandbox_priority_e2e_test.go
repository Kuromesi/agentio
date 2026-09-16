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
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	registrykube "github.com/openkruise/agentio/pkg/registry/kubernetes"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// TestSandboxPriorityEndToEnd exercises informer -> registry -> compiler ->
// publication -> real gRPC Delta ADS. Only the Kubernetes API and authentication
// are fake; no compiled resources or expected ordering are injected into xDS.
func TestSandboxPriorityEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const sandboxUID = "demo--priority"
	client := priorityKubeClient{Client: kube.NewFakeClient()}
	_, err := client.AgentsAPI().AgentsV1alpha1().Sandboxes("demo").Create(ctx, &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name: "priority", Namespace: "demo", UID: "sandbox-object-uid",
			Labels: map[string]string{"app": "priority-client"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := registrykube.New(client, registrykube.Options{
		SandboxMode: true, ClusterID: "test", TrustDomain: "cluster.local",
		RootNamespace: "agentio-system", DebounceAfter: time.Millisecond,
		DebounceMax: 5 * time.Millisecond,
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}
	client.Run(ctx.Done())
	resourceCompiler, err := compiler.New(compiler.Inputs{
		SandboxMode: true, ClusterID: "test", TrustDomain: "cluster.local",
		RootNamespace: "agentio-system", DiscoveryAddress: "agentiod:15012",
		Pods: registry.Pods, KubernetesServices: registry.KubernetesServices,
		EndpointSlices: registry.EndpointSlices, Sandboxes: registry.Sandboxes,
		Workloads: registry.Workloads, Services: registry.Services,
		Endpoints: registry.Endpoints, Gateways: registry.Gateways,
		TrafficPolicies: registry.TrafficPolicies, SecurityProfiles: registry.SecurityProfiles,
		GatewayPatches: registry.GatewayPatches, Telemetry: registry.Telemetry,
		TelemetryProviderOverrides: registry.TelemetryProviderOverrides,
		AgentioConfig:              registry.AgentioConfig,
	}, krt.NewOptionsBuilder(ctx.Done(), "priority-e2e", nil))
	if err != nil {
		t.Fatal(err)
	}
	store := xdsstore.New(selectionSnapshot(t, nil))
	controller, err := NewController(resourceCompiler, store, time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-controllerDone; err != nil {
			t.Errorf("publication controller: %v", err)
		}
	})

	// Gateway scope can observe unbound Sandboxes. No runtime readiness or
	// backing Pod is needed to validate the complete published policy view.
	scope := gatewayScope()
	server, err := NewServer(fakeAuthenticator{caller: model.PeerIdentity{
		Principal: scope.Principal, AttestedBy: model.AttestationKubernetes,
	}}, fakeResolver{scope: scope}.scopeFuncs(), store, resourceCompiler.HasSynced,
		16, map[string]ResourceGenerator{model.SandboxType: SandboxGenerator{}, model.TrafficPolicyType: TrafficPolicyGenerator{}}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		// Serve closes the listener before returning, including when Stop wins startup.
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve Delta ADS: %v", err)
		}
	})
	conn, err := grpc.NewClient("passthrough:///priority-e2e",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close Delta ADS connection: %v", err)
		}
	})

	// Create the larger priority value first: priority must outrank creation time.
	// The fake API does not assign creation timestamps, so supply them explicitly.
	local, err := client.AgentsAPI().AgentsV1alpha1().TrafficPolicies("demo").Create(ctx,
		&agentsv1alpha1.TrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "a-local-allow", Namespace: "demo", CreationTimestamp: metav1.NewTime(time.Unix(100, 0)),
			},
			Spec: priorityPolicySpec(100, agentsv1alpha1.RuleActionAllow),
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	global, err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Create(ctx,
		&agentsv1alpha1.GlobalTrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "z-global-deny", CreationTimestamp: metav1.NewTime(time.Unix(200, 0)),
			},
			Spec: priorityPolicySpec(10, agentsv1alpha1.RuleActionReject),
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !resourceCompiler.WaitUntilSynced(ctx.Done()) {
		t.Fatal("compiler did not sync")
	}
	stream, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(nodeRequest(model.TrafficPolicyType)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(nodeRequest(model.SandboxType, "*")); err != nil {
		t.Fatal(err)
	}

	globalRules := []string{"trafficPolicies/" + global.Name}
	localRules := []string{"namespaces/demo/trafficPolicies/" + local.Name}
	previous := ""
	bodies := map[string]*securityv1.TrafficPolicy{}
	var latest *sandboxv1.Sandbox
	var latestVersion string
	receive := func() *discoveryv3.DeltaDiscoveryResponse {
		t.Helper()
		response, err := stream.Recv()
		if err != nil {
			t.Fatalf("receive policies: %v; compiler failures: %v", err, resourceCompiler.Failures())
		}
		if err := stream.Send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce}); err != nil {
			t.Fatal(err)
		}
		for _, resource := range response.Resources {
			switch response.TypeUrl {
			case model.TrafficPolicyType:
				body := new(securityv1.TrafficPolicy)
				if err := resource.Resource.UnmarshalTo(body); err != nil {
					t.Fatal(err)
				}
				bodies[resource.Name] = body
			case model.SandboxType:
				if resource.Name != sandboxUID {
					continue
				}
				latest = new(sandboxv1.Sandbox)
				if err := resource.Resource.UnmarshalTo(latest); err != nil {
					t.Fatal(err)
				}
				latestVersion = resource.Version
				if latest.TrafficPolicy != nil {
					t.Fatal("predefined policies must not be copied inline")
				}
			}
		}
		if response.TypeUrl == model.TrafficPolicyType {
			for _, name := range response.RemovedResources {
				delete(bodies, name)
			}
		}
		return response
	}
	await := func(want ...string) string {
		t.Helper()
		for {
			receive()
			if latest == nil || latestVersion == previous {
				continue
			}
			got := latest.GetPolicyRefs()[model.TrafficPolicyType].GetResourceNames()
			if len(got) != len(want) {
				continue
			}
			complete := true
			for _, name := range want {
				complete = complete && bodies[name] != nil
			}
			if !complete {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("TrafficPolicy reference order = %v, want %v", got, want)
			}
			return latestVersion
		}
	}
	previous = await(append(globalRules, localRules...)...)
	// Alternate the effective order so each step publishes new Sandbox refs.
	for _, priority := range []int32{0, 100, 10, 100, 0, 100, 10} {
		local.Spec.Priority = priority
		local, err = client.AgentsAPI().AgentsV1alpha1().TrafficPolicies("demo").Update(ctx, local, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := append(globalRules, localRules...)
		// At equal priority the older local policy precedes the global policy.
		if priority <= global.Spec.Priority {
			want = append(localRules, globalRules...)
		}
		version := await(want...)
		if version == previous {
			t.Fatal("priority update did not change the delivered resource version")
		}
		previous = version
	}
	// A new same-priority policy with an earlier name must follow existing ones.
	newGlobal, err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Create(ctx,
		&agentsv1alpha1.GlobalTrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "a-new-global", CreationTimestamp: metav1.NewTime(time.Unix(300, 0)),
			},
			Spec: priorityPolicySpec(10, agentsv1alpha1.RuleActionReject),
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	previous = await(localRules[0], globalRules[0], "trafficPolicies/"+newGlobal.Name)
	// A rule-body update is delivered independently, under the same AIP-122 name.
	local.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	local, err = client.AgentsAPI().AgentsV1alpha1().TrafficPolicies("demo").Update(ctx, local, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for bodies[localRules[0]].Egress.Rules[0].Action != securityv1.TrafficPolicy_DENY {
		response := receive()
		if response.TypeUrl == model.SandboxType {
			t.Fatal("body-only change resent Sandbox")
		}
	}
	if err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Delete(ctx, global.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	await(localRules[0], "trafficPolicies/"+newGlobal.Name)
}

func priorityPolicySpec(priority int32, action agentsv1alpha1.RuleAction) agentsv1alpha1.TrafficPolicySpec {
	fallback := agentsv1alpha1.RuleActionAllow
	if action == agentsv1alpha1.RuleActionAllow {
		fallback = agentsv1alpha1.RuleActionReject
	}
	return agentsv1alpha1.TrafficPolicySpec{
		Priority: priority,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "priority-client"}},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{
			{Action: action, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}}},
			{Action: fallback, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}},
		}},
	}
}

// Keep the production delayed informer path, exposing only the installed Agents APIs.
type priorityKubeClient struct{ kube.Client }

func (priorityKubeClient) CrdWatcher() kube.CrdWatcher { return priorityCRDs{} }

type priorityCRDs struct{}

func (priorityCRDs) HasSynced() bool { return true }
func (priorityCRDs) KnownOrCallback(gvr schema.GroupVersionResource, _ func(<-chan struct{})) bool {
	return gvr.Group == agentsv1alpha1.GroupVersion.Group
}
func (priorityCRDs) WaitForCRD(gvr schema.GroupVersionResource, _ <-chan struct{}) bool {
	return gvr.Group == agentsv1alpha1.GroupVersion.Group
}
func (priorityCRDs) Run(stop <-chan struct{}) { <-stop }
