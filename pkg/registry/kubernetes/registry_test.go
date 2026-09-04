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
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

var _ interface {
	ResolveScope(model.PeerIdentity, string) (model.ClientScope, error)
} = (*PodScopeResolver)(nil)

var _ attestation.DelegatedIdentityAuthorizer = (*DelegatedIdentityAuthorizer)(nil)
var _ mitm.GatewayCertificateAuthorizer = (*GatewayCertificateAuthorizer)(nil)

func TestDelegatedAuthorizationUsesNodePrincipalIndex(t *testing.T) {
	ctx := t.Context()

	ztunnel := delegationPod("agentio-system", "ztunnel-abc", "ztunnel", "node-a")
	target := delegationPod("demo", "target", "app", "node-a")
	// Keep the old container name here to pin runtime compatibility.
	target.Spec.Containers = []corev1.Container{{
		Name: "istio-proxy",
		Args: []string{"proxy", "ztunnel"},
		Env: []corev1.EnvVar{
			{Name: "ENABLE_SIDECAR_MODE", Value: "true"},
			{Name: "PROXY_MODE", Value: "dedicated"},
		},
	}}
	objects := []runtime.Object{ztunnel, target}
	for i := range 256 {
		pod := delegationPod("noise", fmt.Sprintf("pod-%03d", i), fmt.Sprintf("account-%03d", i), "node-a")
		pod.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
		objects = append(objects, pod)
	}
	registry := newTestRegistry(t, ctx, objects, nil)

	if got := len(registry.podsByNode.Lookup("node-a")); got != 258 {
		t.Fatalf("node candidates = %d, want 258", got)
	}
	const key = "node-a|spiffe://cluster.local/ns/demo/sa/app"
	candidates := registry.delegationPodsByNodePrincipal.Lookup(key)
	if len(candidates) != 1 || candidates[0].Name != target.Name {
		t.Fatalf("delegation candidates = %#v, want only %s", candidates, target.Name)
	}

	// Authorization must not fall back to the broader node index, whose bucket
	// also contains every unrelated Pod above.
	registry.podsByNode = nil
	caller := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "agentio-system",
				ServiceAccount: "ztunnel",
			},
		},
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: ztunnel.Name,
			WorkloadUID:  string(ztunnel.UID),
		},
	}
	requested := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "app",
		},
	}
	if err := registry.DelegatedIdentityAuthorizer().Authorize(ctx, caller, requested); err != nil {
		t.Fatalf("Authorize denied valid delegation: %v", err)
	}
}
