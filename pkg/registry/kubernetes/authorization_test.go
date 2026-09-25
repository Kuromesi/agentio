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

	configv1 "github.com/openkruise/agentio/api/config/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

func delegationPod(namespace, name, serviceAccount, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: apitypes.UID(namespace + "-" + name)},
		Spec:       corev1.PodSpec{ServiceAccountName: serviceAccount, NodeName: node},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}
}

func TestCertificateSourceDistinguishesPodsSharingPrincipal(t *testing.T) {
	a := delegationPod("demo", "a", "shared", "node-a")
	b := delegationPod("demo", "b", "shared", "node-a")
	remote := delegationPod("demo", "remote", "shared", "node-b")
	node := delegationPod("agentio-system", "ztunnel", "ztunnel", "node-a")
	for _, p := range []*corev1.Pod{a, b, remote} {
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, remote, node}, nil)
	authorizer := r.DelegatedIdentityAuthorizer()
	principal := mustTestPrincipal("cluster.local", "ns/demo/sa/shared")
	for _, tc := range []struct {
		name     string
		caller   *corev1.Pod
		registry string
		key      string
		allow    bool
	}{
		{"self", a, "kubernetes/test", string(a.UID), true},
		{"other Pod with same SA", a, "kubernetes/test", string(b.UID), false},
		{"other Pod self", b, "kubernetes/test", string(b.UID), true},
		{"local delegation a", node, "kubernetes/test", string(a.UID), true},
		{"local delegation b", node, "kubernetes/test", string(b.UID), true},
		{"remote delegation", node, "kubernetes/test", string(remote.UID), false},
		{"wrong registry", node, "kubernetes/other", string(a.UID), false},
		{"unknown instance", node, "kubernetes/test", "unknown", false},
		{"source belongs to different principal", node, "kubernetes/test", string(node.UID), false},
		{"missing key", node, "kubernetes/test", "", false},
		{"principal-only self", a, "", "", true},
		{"principal-only delegation", node, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizer.Authorize(t.Context(), gatewayTestPeer(tc.caller), attestation.CertificateTarget{
				Principal: principal,
				Source:    model.SourceRef{Registry: tc.registry, Key: tc.key},
			})
			if (err == nil) != tc.allow {
				t.Fatalf("Authorize() = %v, want allow=%v", err, tc.allow)
			}
		})
	}
}

func TestDelegatedAuthorizationPreservesIdentityRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.PeerIdentity, *model.Principal, *corev1.Pod, *corev1.Pod)
		allow  bool
	}{
		{name: "node-local ambient workload", allow: true},
		{
			name: "untrusted caller service account",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes.ServiceAccount = "attacker"
			},
		},
		{
			name: "unbound caller token",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes.WorkloadUID = ""
			},
		},
		{
			name: "stale caller UID",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, ztunnel, _ *corev1.Pod) {
				ztunnel.UID = "replacement-uid"
			},
		},
		{
			name: "caller pod service account mismatch",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, ztunnel, _ *corev1.Pod) {
				ztunnel.Spec.ServiceAccountName = "other"
			},
		},
		{
			name: "target on another node",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				target.Spec.NodeName = "node-b"
			},
		},
		{
			name: "target namespace mismatch",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = mustTestPrincipal("cluster.local", "ns/other/sa/app")
			},
		},
		{
			name: "target service account mismatch",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = mustTestPrincipal("cluster.local", "ns/demo/sa/other")
			},
		},
		{
			name: "unsupported requested identity kind",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = model.Principal{}
			},
		},
		{
			name: "unsupported caller identity kind",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes = model.KubernetesPeer{}
			},
		},
		{
			name: "target outside ambient",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				delete(target.Annotations, "ambient.istio.io/redirection")
			},
		},
		{
			name: "terminating target",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				now := metav1.Now()
				target.DeletionTimestamp = &now
			},
		},
		{
			name: "completed target",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				target.Status.Phase = corev1.PodSucceeded
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			ztunnel := delegationPod("agentio-system", "ztunnel-abc", "ztunnel", "node-a")
			target := delegationPod("demo", "workload", "app", "node-a")
			target.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
			caller := model.PeerIdentity{AttestedBy: model.AttestationKubernetes, Kubernetes: model.KubernetesPeer{WorkloadName: ztunnel.Name, WorkloadUID: string(ztunnel.UID), Namespace: "agentio-system", ServiceAccount: "ztunnel"}}
			requested := mustTestPrincipal("cluster.local", "ns/demo/sa/app")
			if test.mutate != nil {
				test.mutate(&caller, &requested, ztunnel, target)
			}
			r := newTestRegistry(t, ctx, []runtime.Object{ztunnel, target}, nil)

			err := r.DelegatedIdentityAuthorizer().Authorize(ctx, caller, attestation.CertificateTarget{Principal: requested})
			if test.allow && err != nil {
				t.Fatalf("Authorize denied valid delegation: %v", err)
			}
			if !test.allow && err == nil {
				t.Fatal("Authorize allowed invalid delegation")
			}
		})
	}
}

func TestGatewayCertificateAuthorizationUsesEffectiveConfiguration(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
		},
	}
	member := delegationPod("agentio-system", "gateway", "egress", "node-a")
	member.Labels = map[string]string{"member": "egress"}
	r := newTestRegistry(t, ctx, []runtime.Object{config, member, gatewayTestService("agentio-system", "egress")}, nil)
	authorizer := r.GatewayCertificateAuthorizer()
	scope := model.ClientScope{
		Class:       model.ClientEgressGateway,
		GatewayKey:  "agentio-system/egress",
		WorkloadUID: "test//Pod/agentio-system/gateway", Source: model.SourceRef{Registry: "kubernetes/test", Key: string(member.UID)},
		Principal: mustTestPrincipal("cluster.local", "ns/agentio-system/sa/egress"),
	}

	if err := authorizer.Authorize(scope); err != nil {
		t.Fatalf("Authorize denied configured gateway: %v", err)
	}
	scope.GatewayKey = "agentio-system/other"
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed an unregistered gateway")
	}
	scope.GatewayKey = "agentio-system/egress"
	scope.Principal = model.Principal{}
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed an empty principal")
	}
}

func TestGatewayCertificateAuthorizationUsesProvidedConfigurationSource(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	gateways := krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "external-egress",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceGatewayAPI,
	}}, krt.WithStop(stop))
	authorizer := NewGatewayCertificateAuthorizer(gateways)
	scope := model.ClientScope{
		Class:       model.ClientEgressGateway,
		GatewayKey:  "agentio-system/external-egress",
		WorkloadUID: "external", Source: model.SourceRef{Registry: "kubernetes/test", Key: "pod"},
		Principal: mustTestPrincipal("cluster.local", "ns/"+("agentio-system")+"/sa/"+("external-egress")),
	}

	if err := authorizer.Authorize(scope); err != nil {
		t.Fatalf("Authorize denied gateway from provided configuration source: %v", err)
	}
	conflict := *gateways.GetKey(scope.GatewayKey)
	conflict.Config = nil
	conflict.Source = model.GatewaySourceConflict
	conflict.Source = model.GatewaySourceConflict
	gateways.ConditionalUpdateObject(conflict)
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed a conflicting gateway declaration")
	}
}
