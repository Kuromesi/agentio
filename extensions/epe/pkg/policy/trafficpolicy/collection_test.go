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

package trafficpolicy

import (
	"fmt"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func TestCollectionHotUpdate(t *testing.T) {
	policy := &agentsv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "actor-egress", Namespace: "sandbox"},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 100,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"kruise.io/actor-name": "actor-a",
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "172.30.199.186/32"}},
			}}},
		},
	}
	agentsCS := agentsfake.NewSimpleClientset(policy)
	RegisterTypes(agentsCS)

	client := kube.NewFakeClient()
	clienttest.MakeCRD(t, client, trafficPolicyGVR)
	clienttest.MakeCRD(t, client, globalTrafficPolicyGVR)
	stop := test.NewStop(t)

	store := NewStore()
	collection := NewCollection(client, nil, stop)
	registration := store.RegisterCollection(collection)
	client.RunAndWait(stop)
	if !registration.WaitUntilSynced(stop) {
		t.Fatal("TrafficPolicy collection handler never synced")
	}

	pod := inputs.Pod{Namespace: "sandbox", Labels: map[string]string{
		"kruise.io/actor-name": "actor-a",
	}}
	req := &httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.199.186", Port: 80}
	assertAllowed := func(want bool) error {
		decision := store.Authorize(pod, req)
		if !decision.Enforced || decision.Allowed != want {
			return fmt.Errorf("decision = %+v, want enforced allow=%v", decision, want)
		}
		return nil
	}
	retry.UntilSuccessOrFail(t, func() error { return assertAllowed(true) }, retry.Timeout(5*time.Second))

	ctx := test.NewContext(t)
	updated := policy.DeepCopy()
	updated.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	if _, err := agentsCS.AgentsV1alpha1().TrafficPolicies("sandbox").Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error { return assertAllowed(false) }, retry.Timeout(5*time.Second))

	if err := agentsCS.AgentsV1alpha1().TrafficPolicies("sandbox").Delete(ctx, policy.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		decision := store.Authorize(pod, req)
		if decision.Enforced || !decision.Allowed {
			return fmt.Errorf("decision after delete = %+v, want compatibility passthrough", decision)
		}
		return nil
	}, retry.Timeout(5*time.Second))
}
