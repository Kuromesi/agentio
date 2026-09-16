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
	"slices"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func managedSandboxPod(name string, injected bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", UID: types.UID(name + "-uid"), Labels: map[string]string{"app": "client"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "client", NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.0.0.1"},
	}
	if injected {
		p.Spec.Containers = []corev1.Container{{Name: "agentio-proxy", Args: []string{"proxy", "ztunnel"}, Env: []corev1.EnvVar{
			{Name: "ENABLE_SIDECAR_MODE", Value: "true"}, {Name: "PROXY_MODE", Value: "dedicated"},
		}}}
	} else {
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	return p
}

func TestRegistryPodSandboxesAndRuntimeOwnership(t *testing.T) {
	for _, kruiseEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("kruise=%t", kruiseEnabled), func(t *testing.T) {
			ctx := t.Context()
			injected, ambient := managedSandboxPod("injected", true), managedSandboxPod("ambient", false)
			ambient.Status.PodIP = "10.0.0.2"
			unmanaged, warm := managedSandboxPod("unmanaged", false), managedSandboxPod("warm", true)
			unmanaged.Annotations = nil
			unmanaged.Status.PodIP, warm.Status.PodIP = "10.0.0.3", "10.0.0.4"
			controller := true
			warm.OwnerReferences = []metav1.OwnerReference{{APIVersion: agentsv1alpha1.GroupVersion.String(), Kind: "Sandbox", Name: "pool", UID: "pool-uid", Controller: &controller}}
			client := &fakeKubeClient{Client: kube.NewFakeClient(injected, ambient, unmanaged, warm),
				watcher: newFakeGatewayCRDWatcher(agentsv1alpha1.GroupVersion.WithResource("sandboxes"))}
			// The host is already classified while its runtime Sandbox is still absent.
			r, err := New(client, Options{ClusterID: "test", TrustDomain: "cluster.local", EnableKruise: kruiseEnabled}, ctx.Done())
			if err != nil {
				t.Fatal(err)
			}
			client.Run(ctx.Done())
			eventually(t, r.HasSynced, "registry synchronized")
			podSandboxes := 3
			if kruiseEnabled {
				podSandboxes = 2
			}
			if got := r.Sandboxes.List(); len(got) != podSandboxes {
				t.Fatalf("expected %d ordinary Pod Sandboxes: %+v", podSandboxes, got)
			}
			if derived := r.Sandboxes.GetKey("workload:warm-uid"); (derived != nil) == kruiseEnabled {
				t.Fatalf("runtime host Pod Sandbox = %+v, kruise enabled = %t", derived, kruiseEnabled)
			}
			for _, p := range []*corev1.Pod{injected, ambient, unmanaged, warm} {
				w := r.Workloads.GetKey(podsource.WorkloadUID("test", p))
				if w == nil {
					t.Fatalf("Workload for %s = %+v", p.Name, w)
				}
			}
			runtime := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "demo", UID: "pool-uid",
				Labels: map[string]string{agentsv1alpha1.LabelSandboxPool: "pool"}},
				Status: agentsv1alpha1.SandboxStatus{PodInfo: agentsv1alpha1.PodInfo{PodUID: warm.UID}}}
			runtime, err = client.AgentsAPI().AgentsV1alpha1().Sandboxes("demo").Create(ctx, runtime, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			runtime.Labels[agentsv1alpha1.LabelSandboxID] = "assigned-sandbox"
			runtime.Labels[agentsv1alpha1.LabelSandboxIsClaimed] = agentsv1alpha1.True
			if _, err = client.AgentsAPI().AgentsV1alpha1().Sandboxes("demo").Update(ctx, runtime, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if kruiseEnabled {
				eventually(t, func() bool {
					s := r.Sandboxes.GetKey("kruise:assigned-sandbox")
					return s != nil && s.Attester != nil && s.Attester.WorkloadUID == podsource.WorkloadUID("test", warm)
				}, "runtime binding joins ordinary Pod Sandboxes")
			}
			// The host has either a runtime Sandbox or a derived Pod Sandbox.
			count := 3
			if len(r.Sandboxes.List()) != count {
				t.Fatal("runtime host produced a duplicate ordinary Sandbox")
			}

			oldUID := "workload:ambient-uid"
			ambient = ambient.DeepCopy()
			ambient.Labels["app"] = "changed"
			if _, err := client.Kube().CoreV1().Pods("demo").Update(ctx, ambient, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				s := r.Sandboxes.GetKey(oldUID)
				return s != nil && s.Labels["app"] == "changed" && s.Attester != nil && s.State == model.SandboxStatePending
			}, "Pending Pod retains binding and updates policy labels")
			if err := client.Kube().CoreV1().Pods("demo").Delete(ctx, ambient.Name, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			ambient.UID = "replacement-uid"
			if _, err := client.Kube().CoreV1().Pods("demo").Create(ctx, ambient, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				return r.Sandboxes.GetKey(oldUID) == nil && r.Sandboxes.GetKey("workload:replacement-uid") != nil && len(r.Sandboxes.List()) == count
			}, "Pod recreation removes previous Sandbox identity")
			ambient.Annotations = nil
			if _, err := client.Kube().CoreV1().Pods("demo").Update(ctx, ambient, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				w := r.Workloads.GetKey(podsource.WorkloadUID("test", ambient))
				return r.Sandboxes.GetKey("workload:replacement-uid") == nil && w != nil
			}, "leaving ambient removes derived Sandbox but retains endpoint")
		})
	}
}

func TestPodSandboxPoliciesReachCompiler(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			ctx := t.Context()
			injected, ambient := managedSandboxPod("injected", true), managedSandboxPod("ambient", false)
			// A disabled runtime must not exclude an otherwise managed Pod from
			// the built-in Sandbox policy path, including native-only output.
			controller := true
			injected.OwnerReferences = []metav1.OwnerReference{{APIVersion: agentsv1alpha1.GroupVersion.String(), Kind: "Sandbox", Name: "actor", UID: "actor-uid", Controller: &controller}}
			ambient.Status.PodIP = "10.0.0.2"
			spec := func(priority int32) agentsv1alpha1.TrafficPolicySpec {
				return agentsv1alpha1.TrafficPolicySpec{Priority: priority, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}}}}}}
			}
			global := &agentsv1alpha1.GlobalTrafficPolicy{ObjectMeta: metav1.ObjectMeta{Name: "global"}, Spec: spec(5)}
			namespace := &agentsv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "namespace"}, Spec: spec(20)}
			selected := &agentsv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "selected"}, Spec: spec(10)}
			selected.Spec.Selector.MatchLabels = map[string]string{"app": "client"}
			security := &agentsv1alpha1.SecurityProfile{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "security"}, Spec: agentsv1alpha1.SecurityProfileSpec{Selector: selected.Spec.Selector, Rules: []agentsv1alpha1.SecurityRule{{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example"}}}}}}}
			config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"}, Data: map[string]string{"config": "egressPolicies:\n- namespaces: [demo]\n  policy: PASSTHROUGH\n"}}
			client := &fakeKubeClient{Client: kube.NewFakeClient(injected, ambient, global, namespace, selected, security, config),
				watcher: newFakeGatewayCRDWatcher(trafficPolicyResource, globalTrafficPolicyResource, securityProfileResource)}
			r, err := New(client, Options{ClusterID: "test", TrustDomain: "cluster.local", RootNamespace: "agentio-system"}, ctx.Done())
			if err != nil {
				t.Fatal(err)
			}
			c, err := compiler.New(compiler.Inputs{
				NativeSandboxPolicies: native, ClusterID: "test", RootNamespace: "agentio-system", TrustDomain: "cluster.local", DiscoveryAddress: "agentiod:15012",
				Pods: r.Pods, KubernetesServices: r.KubernetesServices, EndpointSlices: r.EndpointSlices, Sandboxes: r.Sandboxes, Workloads: r.Workloads,
				Services: r.Services, Endpoints: r.Endpoints, Gateways: r.Gateways, TrafficPolicies: r.TrafficPolicies, SecurityProfiles: r.SecurityProfiles,
				GatewayPatches: r.GatewayPatches, Telemetry: r.Telemetry, TelemetryProviderOverrides: r.TelemetryProviderOverrides, AgentioConfig: r.AgentioConfig,
			}, krt.NewOptionsBuilder(ctx.Done(), "pod-sandbox", nil))
			if err != nil {
				t.Fatal(err)
			}
			client.Run(ctx.Done())
			eventually(t, func() bool { return r.HasSynced() && c.HasSynced() }, "registry and compiler synchronized without Kruise integration")
			snapshot := func() model.ResourceSet {
				s, err := c.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			getSandbox := func(name string) (*sandboxv1.Sandbox, model.Resource) {
				s := &sandboxv1.Sandbox{}
				resource, ok := snapshot().Get(model.ResourceKey{TypeURL: model.SandboxType, Name: "workload:" + name + "-uid"})
				if ok {
					if err := resource.Value.UnmarshalTo(s); err != nil {
						t.Fatal(err)
					}
				}
				return s, resource
			}
			getWorkload := func(name string) *workloadv1.Workload {
				w := &workloadv1.Address{}
				resource, ok := snapshot().Get(model.ResourceKey{TypeURL: model.AddressType, Name: "test//Pod/demo/" + name})
				if ok {
					if err := resource.Value.UnmarshalTo(w); err != nil {
						t.Fatal(err)
					}
				}
				return w.GetWorkload()
			}
			refs := []string{"trafficPolicies/global", "namespaces/demo/trafficPolicies/selected", "namespaces/demo/trafficPolicies/namespace"}
			eventually(t, func() bool {
				for _, name := range []string{"injected", "ambient"} {
					s, _ := getSandbox(name)
					w := getWorkload(name)
					if !slices.Equal(s.PolicyRefs[model.TrafficPolicyType].GetResourceNames(), refs) || len(s.Extensions) != 1 || len(s.GetEgressRouting().GetRoutes()) != 1 || w == nil {
						return false
					}
					if !native && (len(w.AuthorizationPolicies) != 2 || len(w.Extensions) != 3) {
						return false
					}
				}
				return true
			}, "global, namespace, selector, SNI and egress policies use Sandbox output")
			for _, name := range []string{"injected", "ambient"} {
				s, _ := getSandbox(name)
				if s.State != sandboxv1.SandboxState_SANDBOX_STATE_PENDING || s.Attester.WorkloadUid != "test//Pod/demo/"+name || s.TrafficPolicy != nil {
					t.Fatalf("derived Sandbox = %v", s)
				}
				if c.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, "test//Pod/demo/"+name)) != nil {
					t.Fatal("managed Pod independently matches Workload policies")
				}
				w := getWorkload(name)
				if native && (len(w.AuthorizationPolicies) != 0 || len(w.Extensions) != 1) {
					t.Fatalf("native mode retains Workload policies: %v", w)
				}
			}
			if len(snapshot().List(model.TrafficPolicyType)) != 3 {
				t.Fatal("shared policies were duplicated per Pod")
			}
			if failures := c.Failures(); len(failures) != 0 {
				t.Fatalf("compile failures: %v", failures)
			}

			// A shared body update changes one policy, without republishing Pod Sandboxes.
			_, before := getSandbox("injected")
			key := model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: refs[0]}
			original, _ := snapshot().Get(key)
			global.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
			if _, err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Update(ctx, global, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool { updated, ok := snapshot().Get(key); return ok && updated.Hash != original.Hash }, "shared body update published")
			_, after := getSandbox("injected")
			if after.Hash != before.Hash {
				t.Fatal("shared body update rewrote derived Sandbox")
			}

			ambient.Labels = map[string]string{"app": "other"}
			if _, err := client.Kube().CoreV1().Pods("demo").Update(ctx, ambient, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				s, _ := getSandbox("ambient")
				return slices.Equal(s.PolicyRefs[model.TrafficPolicyType].GetResourceNames(), []string{refs[0], refs[2]}) && len(s.Extensions) == 0
			}, "Pod label change reselects only Sandbox policy bindings")
			if !native {
				// Existing legacy DENY routing must survive the move to Sandbox ownership.
				config.Data["config"] = "egressPolicies:\n- namespaces: [demo]\n  policy: DENY\n"
				if _, err := client.Kube().CoreV1().ConfigMaps("agentio-system").Update(ctx, config, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				eventually(t, func() bool {
					w := getWorkload("injected")
					for _, ext := range w.GetExtensions() {
						if ext.Name == "egress-policies" {
							p := &extensionsv1.EgressPolicies{}
							return ext.Config.UnmarshalTo(p) == nil && len(p.EgressPolicies) == 1 && p.EgressPolicies[0].Policy == extensionsv1.EgressPolicyAction_DENY
						}
					}
					return false
				}, "legacy DENY routing preserved")
			}
		})
	}
}
