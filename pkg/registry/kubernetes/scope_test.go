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

package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestResolveScopeAuthorizesRegisteredGatewayServiceAccounts(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`},
	}
	valid := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	valid.UID = "valid-uid"
	implicit := egressPod("demo", "egress-rollout-b", "egress", "10.0.0.2")
	implicit.UID = "implicit-uid"
	implicit.Labels = nil
	spoofed := egressPod("demo", "attacker", "egress", "10.0.0.3")
	spoofed.UID = "spoofed-uid"
	spoofed.Spec.ServiceAccountName = "attacker"
	unconfigured := egressPod("demo", "missing", "missing", "10.0.0.4")
	unconfigured.UID = "unconfigured-uid"
	r := newTestRegistry(t, ctx, []runtime.Object{config, valid, implicit, spoofed, unconfigured}, nil)

	for _, test := range []struct {
		name           string
		pod            *corev1.Pod
		serviceAccount string
		wantClass      model.ClientClass
		wantKey        string
		wantSandboxUID string
	}{
		{name: "explicit config with standard label", pod: valid, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "manual deployment without labels", pod: implicit, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "label cannot grant gateway scope", pod: spoofed, serviceAccount: "attacker", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/attacker"},
		{name: "unregistered identity gets only sandbox scope", pod: unconfigured, serviceAccount: "missing", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := model.Principal{
				Kind:        model.PrincipalServiceAccount,
				TrustDomain: "cluster.local",
				ServiceAccount: model.ServiceAccountRef{
					Namespace:      test.pod.Namespace,
					ServiceAccount: test.serviceAccount,
				},
			}
			peer := model.PeerIdentity{
				Principal:  principal,
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{
					WorkloadName: test.pod.Name,
					WorkloadUID:  string(test.pod.UID),
				},
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != test.wantClass || scope.GatewayKey != test.wantKey || scope.WorkloadUID != test.wantSandboxUID {
				t.Fatalf("ResolveScope() = %+v, want class %s gateway %q sandbox %q", scope, test.wantClass, test.wantKey, test.wantSandboxUID)
			}
		})
	}
}

func TestResolveScopeAuthorizesGatewayAPIServiceAccount(t *testing.T) {
	ctx := t.Context()
	watcher := newFakeGatewayCRDWatcher()
	pod := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	pod.UID = "gateway-uid"
	r := newGatewayTestRegistry(t, ctx, watcher, ownedGatewayClass(), ownedGateway(), pod)
	watcher.install(gatewayResource, ctx.Done())
	watcher.install(gatewayClassResource, ctx.Done())
	eventually(t, func() bool { return r.Gateways.GetKey("demo/egress") != nil }, "Gateway API registration")

	peer := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "egress",
			},
		},
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: pod.Name,
			WorkloadUID:  string(pod.UID),
		},
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatalf("ResolveScope(): %v", err)
	}
	if scope.Class != model.ClientEgressGateway || scope.GatewayKey != "demo/egress" {
		t.Fatalf("ResolveScope() = %+v, want Gateway API-owned gateway demo/egress", scope)
	}
}

// Unbound tokens cannot establish Pod or node ownership.
func TestResolveScopeRejectsUnboundTokensForPodScopes(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`},
	}
	gateway := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	gateway.UID = "gateway-uid"
	sandbox := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.5"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config, gateway, sandbox}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	gatewayPrincipal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "egress",
		},
	}
	sandboxPrincipal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "app",
		},
	}

	for _, test := range []struct {
		name      string
		principal model.Principal
		bound     bool
		podName   string
		podUID    string
		wantClass model.ClientClass
		wantKey   string
	}{
		{name: "unbound token claiming gateway pod", principal: gatewayPrincipal, podName: "egress-rollout-a"},
		{name: "unbound token asserting gateway pod UID", principal: gatewayPrincipal, podName: "egress-rollout-a", podUID: "gateway-uid"},
		{name: "unbound token claiming sandbox pod", principal: sandboxPrincipal, podName: "sandbox"},
		{
			name:      "bound token resolves gateway scope",
			principal: gatewayPrincipal,
			bound:     true,
			podName:   "egress-rollout-a",
			podUID:    "gateway-uid",
			wantClass: model.ClientEgressGateway,
			wantKey:   "demo/egress",
		},
		{
			name:      "bound token resolves sandbox scope",
			principal: sandboxPrincipal,
			bound:     true,
			podName:   "sandbox",
			podUID:    "sandbox-uid",
			wantClass: model.ClientDedicatedZTunnel,
			wantKey:   "test//Pod/demo/sandbox",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := model.PeerIdentity{
				Principal:  test.principal,
				AttestedBy: model.AttestationKubernetes,
			}
			if test.bound {
				peer.Kubernetes.WorkloadName = test.podName
				peer.Kubernetes.WorkloadUID = test.podUID
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if !test.bound {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want unbound token rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != test.wantClass {
				t.Fatalf("ResolveScope() class = %v, want %v", scope.Class, test.wantClass)
			}
			if test.wantClass == model.ClientEgressGateway && scope.GatewayKey != test.wantKey {
				t.Fatalf("ResolveScope() gateway key = %q, want %q", scope.GatewayKey, test.wantKey)
			}
			if test.wantClass == model.ClientDedicatedZTunnel && scope.WorkloadUID != test.wantKey {
				t.Fatalf("ResolveScope() sandbox UID = %q, want %q", scope.WorkloadUID, test.wantKey)
			}
		})
	}
}

func TestResolveSharedZTunnelRequiresPodBoundToken(t *testing.T) {
	ctx := t.Context()
	ztunnel := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-abc",
			UID:       "ztunnel-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-b",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.1",
		},
	}
	elsewhere := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-xyz",
			UID:       "elsewhere-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-c",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.2",
		},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{ztunnel, elsewhere}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	principal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "agentio-system",
			ServiceAccount: "ztunnel",
		},
	}
	unbound := model.PeerIdentity{
		Principal:  principal,
		AttestedBy: model.AttestationKubernetes,
	}
	if scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(unbound, "node-b"); err == nil {
		t.Fatalf("ResolveScope() = %+v, want unbound node token rejection", scope)
	}

	bound := unbound
	bound.Kubernetes = model.KubernetesPeer{
		WorkloadName: ztunnel.Name,
		WorkloadUID:  string(ztunnel.UID),
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(bound, "node-b")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Class != model.ClientSharedZTunnel || scope.NodeName != "node-b" {
		t.Fatalf("scope = %+v", scope)
	}
}

// A token bound to a Pod UID must not grant a same-name replacement Pod.
func TestResolveScopeRejectsReplacedPodUID(t *testing.T) {
	ctx := t.Context()
	live := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "replacement-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{live}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 1 }, "replacement pod loaded")

	for _, test := range []struct {
		name      string
		uid       string
		wantError bool
	}{
		{name: "stale bound UID", uid: "original-uid", wantError: true},
		{name: "matching bound UID", uid: "replacement-uid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := model.PeerIdentity{
				Principal: model.Principal{
					Kind:        model.PrincipalServiceAccount,
					TrustDomain: "cluster.local",
					ServiceAccount: model.ServiceAccountRef{
						Namespace:      "demo",
						ServiceAccount: "app",
					},
				},
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{WorkloadName: "sandbox", WorkloadUID: test.uid, NodeName: "node-a"},
			}

			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "node-a")
			if test.wantError {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want stale bound UID rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope() matching UID: %v", err)
			}
			if scope.Class != model.ClientDedicatedZTunnel || scope.WorkloadUID != "test//Pod/demo/sandbox" {
				t.Fatalf("ResolveScope() = %+v, want live replacement sandbox scope", scope)
			}
		})
	}
}

func TestResolveScopeUsesFinalWorkloadCollection(t *testing.T) {
	ctx := t.Context()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod}, nil)
	workload := r.Workloads.GetKey("test//Pod/demo/sandbox")
	if workload == nil {
		t.Fatal("default Pod workload was not created")
	}
	finalWorkloads := krt.NewStaticCollection[model.Workload](nil, []model.Workload{*workload}, krt.WithStop(ctx.Done()))

	peer := model.PeerIdentity{
		Principal:  workload.Principal,
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: pod.Name,
			WorkloadUID:  string(pod.UID),
		},
	}
	scope, err := r.PodScopeResolver(finalWorkloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadUID != workload.UID {
		t.Fatalf("sandbox scope = %q, want final Workload binding", scope.WorkloadUID)
	}
}

// An unsupported Principal kind has no Pod ownership to prove.
func TestResolveScopeRejectsUnsupportedPrincipalKind(t *testing.T) {
	ctx := t.Context()
	r := newTestRegistry(t, ctx, nil, nil)

	peer := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        "workload-v1",
			TrustDomain: "cluster.local",
		},
		AttestedBy: model.AttestationKubernetes,
	}
	if _, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, ""); err == nil {
		t.Fatal("unsupported Principal kind resolved a Kubernetes scope")
	}
}

func TestResolveScopeAuthenticatesEmptyWorker(t *testing.T) {
	ctx := t.Context()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "worker", UID: "worker-pod"},
		Spec:       corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod}, nil)
	workload := r.Workloads.GetKey("test//Pod/demo/worker")
	if workload == nil {
		t.Fatal("worker missing")
	}

	workloads := krt.NewStaticCollection[model.Workload](nil, []model.Workload{*workload}, krt.WithStop(ctx.Done()))
	resolver := r.PodScopeResolver(workloads)
	peer := model.PeerIdentity{
		Principal:  workload.Principal,
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{WorkloadName: pod.Name, WorkloadUID: string(pod.UID)},
	}
	scope, err := resolver.ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadUID != workload.UID || scope.SourceUID != string(pod.UID) {
		t.Fatalf("scope %+v", scope)
	}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	peer.Kubernetes.WorkloadUID = "spoofed"
	if _, err := resolver.ResolveScope(peer, ""); err == nil {
		t.Fatal("unbound Pod UID gained worker scope")
	}
}
