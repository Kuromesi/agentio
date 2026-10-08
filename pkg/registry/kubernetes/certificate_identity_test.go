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

	"github.com/openkruise/agentio/pkg/model"
)

func TestCertificateAttestationAndGatewayMembership(t *testing.T) {
	a := delegationPod("demo", "a", "shared", "node-a")
	b := delegationPod("demo", "b", "shared", "node-a")
	node := delegationPod("agentio-system", "ztunnel", "ztunnel", "node-a")
	gateway := delegationPod("agentio-system", "gateway", "unrelated-bootstrap-sa", "node-a")
	lookalike := delegationPod("agentio-system", "lookalike", "unrelated-bootstrap-sa", "node-a")
	lookalike.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "different-gateway"}
	a.UID, b.UID, node.UID, gateway.UID, lookalike.UID = "pod-a", "pod-b", "node-pod", "gateway-pod", "lookalike-pod"
	for _, p := range []*corev1.Pod{a, b, node, gateway, lookalike} {
		p.Status.PodIP = "10.0.0.1"
		p.Status.Phase = corev1.PodRunning
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{"config": `egressGateways:
- name: egress
  namespace: agentio-system
`},
	}
	gateway.Labels = map[string]string{"gateway-member": "egress", "gateway.networking.k8s.io/gateway-name": "egress"}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "egress"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"gateway-member": "egress"}},
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, node, gateway, lookalike, config, service}, nil)
	caller := func(p *corev1.Pod) model.PeerIdentity {
		return model.PeerIdentity{
			AttestedBy: model.AttestationKubernetes,
			Kubernetes: model.KubernetesPeer{
				WorkloadName:   p.Name,
				WorkloadUID:    string(p.UID),
				Namespace:      p.Namespace,
				ServiceAccount: p.Spec.ServiceAccountName,
			},
		}
	}
	auth := r.DelegatedIdentityAuthorizer()
	target := func(p *corev1.Pod) model.Principal {
		return r.Workloads.GetKey("test//Pod/" + p.Namespace + "/" + p.Name).Principal
	}
	aid, bid, gid := target(a), target(b), target(gateway)
	for _, tc := range []struct {
		name  string
		peer  model.PeerIdentity
		id    model.Principal
		allow bool
	}{
		{"own pod", caller(a), aid, true},
		{"unregistered principal", caller(a), mustTestPrincipal("cluster.local", "ns/demo/sa/app"), false},
		{"same SA different pod", caller(a), bid, false},
		{"gateway role forgery", caller(a), gid, false},
		{"bound gateway with independent SA", caller(gateway), gid, true},
		{"same SA non-member shares gateway certificate identity", caller(lookalike), gid, true},
		{"non-member retains own workload identity", caller(lookalike), target(lookalike), true},
		{"node-local delegation", caller(node), bid, true},
		{"node-local eligible gateway delegation", caller(node), gid, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.Authorize(t.Context(), tc.peer, tc.id)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v, error=%v", tc.allow, err)
			}
		})
	}
	unbound := caller(a)
	unbound.Kubernetes.WorkloadUID = ""
	if err := auth.Authorize(t.Context(), unbound, aid); err == nil {
		t.Fatal("accepted unbound token")
	}
	stale := caller(a)
	stale.Kubernetes.WorkloadUID = "replaced"
	if err := auth.Authorize(t.Context(), stale, aid); err == nil {
		t.Fatal("accepted stale token")
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(caller(gateway), "")
	wantSource := model.SourceRef{Registry: "kubernetes/test", Key: string(gateway.UID)}
	if err != nil || scope.Principal != gid || scope.Source != wantSource {
		t.Fatalf("gateway scope: %v %v", scope, err)
	}
	if err := r.GatewayCertificateAuthorizer().Authorize(scope); err != nil {
		t.Fatal(err)
	}
	if scope, err := r.PodScopeResolver(r.Workloads).
		ResolveScope(caller(lookalike), ""); err != nil ||
		scope.Class == model.ClientEgressGateway {
		t.Fatal("non-member acquired gateway scope")
	}
	unboundGateway := model.ClientScope{
		Class:      model.ClientEgressGateway,
		Principal:  gid,
		GatewayKey: "agentio-system/egress",
	}
	if err := r.GatewayCertificateAuthorizer().Authorize(unboundGateway); err == nil {
		t.Fatal("gateway scope without source binding acquired MITM authority")
	}
	b.Spec.NodeName = "node-b"
	if _, err := r.client.CoreV1().Pods(b.Namespace).Update(t.Context(), b, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		return auth.Authorize(t.Context(), caller(node), bid) != nil
	}, "cross-node delegation denied")
}

func TestWorkloadPrincipalAuthorization(t *testing.T) {
	a := delegationPod("demo", "a", "shared", "node-a")
	b := delegationPod("demo", "b", "shared", "node-a")
	remote := delegationPod("demo", "remote", "shared", "node-b")
	node := delegationPod("agentio-system", "ztunnel", "ztunnel", "node-a")
	for _, p := range []*corev1.Pod{a, b, remote} {
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, remote, node}, nil)
	auth := r.DelegatedIdentityAuthorizer()
	wa := r.Workloads.GetKey("test//Pod/demo/a")
	wb := r.Workloads.GetKey("test//Pod/demo/b")
	if wa == nil || wb == nil || wa.Principal == wb.Principal {
		t.Fatal("Pods sharing an SA must have distinct principals")
	}
	if wa.Principal.String() != "spiffe://cluster.local/cluster/test/ns/demo/workload/a" {
		t.Fatalf("principal=%s", wa.Principal)
	}
	for _, tc := range []struct {
		name   string
		caller *corev1.Pod
		target model.Principal
		allow  bool
	}{
		{"self", a, wa.Principal, true},
		{"same SA other Pod", a, wb.Principal, false},
		{"node-local principal", node, wb.Principal, true},
		{
			"cross-node target", node,
			mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/remote"),
			false,
		},
		{
			"unknown target", node,
			mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/unknown"),
			false,
		},
		{
			"different cluster", node,
			mustTestPrincipal("cluster.local", "cluster/other/ns/demo/workload/b"),
			false,
		},
		{
			"different namespace", node,
			mustTestPrincipal("cluster.local", "cluster/test/ns/other/workload/b"),
			false,
		},
		{
			"unsupported format", node,
			mustTestPrincipal("cluster.local", "cluster/test/ns/demo/service/b"),
			false,
		},
		{
			"old principal", node,
			mustTestPrincipal("cluster.local", "ns/demo/sa/shared"),
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.Authorize(t.Context(), gatewayTestPeer(tc.caller), tc.target)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v, error=%v", tc.allow, err)
			}
		})
	}
	stale := gatewayTestPeer(a)
	stale.Kubernetes.WorkloadUID = "previous-pod"
	if err := auth.Authorize(t.Context(), stale, wa.Principal); err == nil {
		t.Fatal("stale Pod token accepted")
	}
}

func TestSameNameReplacementRetainsPrincipalAndRejectsOldToken(t *testing.T) {
	pod := delegationPod("demo", "app", "shared", "node-a")
	r := newTestRegistry(t, t.Context(), []runtime.Object{pod}, nil)
	authorizer := r.DelegatedIdentityAuthorizer()
	principal := mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/app")
	if err := authorizer.Authorize(t.Context(), gatewayTestPeer(pod), principal); err != nil {
		t.Fatal(err)
	}
	if err := r.client.CoreV1().Pods(pod.Namespace).Delete(t.Context(), pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := pod.DeepCopy()
	replacement.UID = "replacement-uid"
	replacement.ResourceVersion = ""
	if _, err := r.client.CoreV1().Pods(pod.Namespace).
		Create(t.Context(), replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		w := r.Workloads.GetKey("test//Pod/demo/app")
		return w != nil && w.Principal == principal && w.Source.Key == string(replacement.UID)
	}, "same-name replacement retains its principal with a new source")
	if err := authorizer.Authorize(t.Context(), gatewayTestPeer(pod), principal); err == nil {
		t.Fatal("old Pod token acquired the replacement's certificate")
	}
	if err := authorizer.Authorize(t.Context(), gatewayTestPeer(replacement), principal); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayReplicasShareServiceAccountPrincipal(t *testing.T) {
	a := delegationPod("demo", "gateway-a", "egress", "node-a")
	b := delegationPod("demo", "gateway-b", "egress", "node-b")
	for _, pod := range []*corev1.Pod{a, b} {
		pod.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}
	}
	ordinary := delegationPod("demo", "app", "app", "node-a")
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data:       map[string]string{"config": "egressGateways:\n- namespace: demo\n  name: egress\n"},
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, ordinary, config}, nil)
	authorizer := r.DelegatedIdentityAuthorizer()
	shared := mustTestPrincipal("cluster.local", "ns/demo/sa/egress")
	for _, pod := range []*corev1.Pod{a, b} {
		workload := r.Workloads.GetKey("test//Pod/demo/" + pod.Name)
		if workload == nil || workload.Principal != shared || workload.GatewayKey != "demo/egress" {
			t.Fatalf("gateway Workload=%+v", workload)
		}
		if err := authorizer.Authorize(t.Context(), gatewayTestPeer(pod), shared); err != nil {
			t.Fatal(err)
		}
		own := mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/"+pod.Name)
		if err := authorizer.Authorize(t.Context(), gatewayTestPeer(pod), own); err != nil {
			t.Fatalf("gateway Pod cannot request its own workload identity: %v", err)
		}
	}
	workload := r.Workloads.GetKey("test//Pod/demo/app")
	if workload == nil || workload.Principal.String() != "spiffe://cluster.local/cluster/test/ns/demo/workload/app" {
		t.Fatalf("ordinary Workload=%+v", workload)
	}
	if err := authorizer.Authorize(t.Context(), gatewayTestPeer(ordinary), shared); err == nil {
		t.Fatal("ordinary caller acquired gateway service-account identity")
	}
}
