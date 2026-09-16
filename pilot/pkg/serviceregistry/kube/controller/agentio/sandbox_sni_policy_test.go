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

package agentio

import (
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metadatafake "k8s.io/client-go/metadata/fake"
	"k8s.io/utils/ptr"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func sniTestSandbox(namespace, name, rules string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "agents.kruise.io/v1alpha1", Kind: "Sandbox"},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name,
			Annotations: map[string]string{sandboxSecurityRulesAnnotation: rules}},
	}
}

func TestBindablePolicyFromSandbox(t *testing.T) {
	for _, tt := range []struct {
		name, rules string
		hosts       []string
		invalid     bool
	}{
		{name: "no annotation"},
		{name: "HTTPS domains", rules: `[{"name":"r","match":[{"domains":["API.Example.COM.","*.Example.com","api.example.com"]},{"domains":["*"],"schemes":["HTTP","HTTPS"]},{"domains":["plain.example.com"],"schemes":["http"]}],"actions":{"block":{}}}]`, hosts: []string{"api.example.com", "*.example.com", "*"}},
		{name: "HTTP only", rules: `[{"match":[{"domains":["example.com"],"schemes":["http"]}]}]`},
		{name: "empty array", rules: `[]`, invalid: true},
		{name: "null", rules: `null`, invalid: true},
		{name: "malformed JSON", rules: `[`, invalid: true},
		{name: "unknown field", rules: `[{"matches":[]}]`, invalid: true},
		{name: "invalid domain", rules: `[{"match":[{"domains":["bad.*.com"]}]}]`, invalid: true},
		{name: "trailing JSON", rules: `[{"match":[{"domains":["example.com"]}]}] {}`, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := sniTestSandbox("ns", "shared", tt.rules)
			before := sandbox.DeepCopy()
			got, err := bindablePolicyFromSandbox(sandbox)
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, want invalid %v", err, tt.invalid)
			}
			if !reflect.DeepEqual(sandbox, before) {
				t.Fatal("converter mutated source metadata")
			}
			if len(tt.hosts) == 0 {
				if got != nil {
					t.Fatalf("unexpected policy: %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("missing policy")
			}
			want := &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, tt.hosts...)}}
			if !proto.Equal(got.Resource, want) {
				t.Fatalf("policy = %v, want %v", got.Resource, want)
			}
			if got.Name != "sandbox/ns/shared" || got.PodName != "shared" || got.Namespace != "ns" {
				t.Fatalf("wrong policy identity: %+v", got)
			}
			if got.Selects("ns", nil) {
				t.Fatal("inline policy participated in label selection")
			}
			attachment := policyAttachmentFromBindablePolicy(*got)
			if attachment.PodName != got.PodName || attachment.Selects("ns", nil) {
				t.Fatalf("wrong attachment: %+v", attachment)
			}
			changed := *got
			changed.PodName = "other"
			if got.Equals(changed) || attachment.Equals(*policyAttachmentFromBindablePolicy(changed)) {
				t.Fatal("policy equality ignored Pod identity")
			}
		})
	}
	for _, sandbox := range []*metav1.PartialObjectMetadata{
		sniTestSandbox("", "pod", `[{"match":[{"domains":["example.com"]}]}]`),
		sniTestSandbox("ns", "", `[{"match":[{"domains":["example.com"]}]}]`),
	} {
		if got, err := bindablePolicyFromSandbox(sandbox); got != nil || err == nil {
			t.Fatalf("accepted incomplete identity: %+v, %v", got, err)
		}
	}
}

// Exercise the real metadata informer through policy selection and the inline
// Workload payload, including startup without the optional CRD and late arrival.
func TestSandboxSNIPolicyLifecycle(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	test.SetForTest(t, &features.KrtEventDistributeDebounce, time.Duration(0))
	test.SetForTest(t, &features.KrtEventDistributeDebounceMax, time.Duration(0))
	client := kube.NewFakeClient()
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "sandbox-sni-test", krt.GlobalDebugHandler)
	sources := newSandboxSecurityRulesCollection(client, stop, opts)
	profiles := krt.NewStaticCollection[*agentsv1alpha1.SecurityProfile](nil, nil, opts.WithName("profiles")...)
	globals := krt.NewStaticCollection[*agentsv1alpha1.GlobalSecurityProfile](nil, nil, opts.WithName("globals")...)
	controller := &Controller{securityProfiles: profiles, globalSecurityProfiles: globals, sandboxSecurityRules: sources}
	controller.initBindablePolicies(opts)
	target := sniTestWorkload("shared", "ns", map[string]string{"app": "same"})
	other := sniTestWorkload("other", "ns", target.Labels)
	crossNamespace := sniTestWorkload("shared", "elsewhere", target.Labels)
	nonPod := sniTestWorkload("shared", "ns", target.Labels)
	nonPod.Workload.Uid = "workload-entry"
	nonPod.Source = kind.WorkloadEntry
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{target, other, crossNamespace, nonPod}, opts.WithName("workloads")...)
	inline := controller.BuildWorkloadSNIPoliciesCollection(workloads, opts)
	client.RunAndWait(stop)
	synced := make(chan struct{})
	go func() {
		if inline.WaitUntilSynced(stop) {
			close(synced)
		}
	}()
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("SNI pipeline did not sync without Sandbox CRD")
	}
	if len(inline.List()) != 0 {
		t.Fatal("unexpected SNI policy before sources exist")
	}

	// The independent CR deliberately shares the Sandbox's namespace/name.
	profiles.UpdateObject(&agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "shared"},
		Spec:       agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"crd.example.com"}}}}}},
	})
	check := func(sandboxDomain string) {
		t.Helper()
		retry.UntilSuccessOrFail(t, func() error {
			for _, w := range []model.WorkloadInfo{target, other, crossNamespace, nonPod} {
				got := inline.GetKey(w.ResourceName())
				if w.ResourceName() == crossNamespace.ResourceName() || w.ResourceName() == nonPod.ResourceName() {
					if got != nil {
						return fmt.Errorf("policy leaked to %s: %v", w.ResourceName(), got.Policy)
					}
					continue
				}
				want := map[string]bool{"crd.example.com": true}
				if w.ResourceName() == target.ResourceName() && sandboxDomain != "" {
					want[sandboxDomain] = true
				}
				if got == nil {
					return fmt.Errorf("missing policy for %s", w.ResourceName())
				}
				hosts := map[string]bool{}
				for _, rule := range got.Policy.Rules {
					if rule.Action != extensions.SniAction_SNI_ACTION_TLS_TERMINATION {
						return fmt.Errorf("unexpected action: %v", rule.Action)
					}
					for _, host := range rule.Match.Sni {
						hosts[host] = true
					}
				}
				if !reflect.DeepEqual(hosts, want) {
					return fmt.Errorf("%s hosts = %v, want %v", w.ResourceName(), hosts, want)
				}
			}
			return nil
		}, retry.Timeout(5*time.Second), retry.Converge(5))
	}
	check("")
	untouched := inline.GetKey(other.ResourceName()).Policy
	clienttest.MakeCRD(t, client, sandboxGVR)
	metadata := client.Metadata().Resource(sandboxGVR).Namespace("ns").(metadatafake.MetadataClient)
	rules := func(domain string) string {
		return fmt.Sprintf(`[{"name":"r","match":[{"domains":[%q]}],"actions":{"block":{}}}]`, domain)
	}
	sandbox, err := metadata.CreateFake(sniTestSandbox("ns", "shared", rules("initial.example.com")), metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	check("initial.example.com")
	if controller.bindablePolicies.GetKey(xdsmodel.SniTrafficPolicyType+"|ns/shared") == nil ||
		controller.bindablePolicies.GetKey(xdsmodel.SniTrafficPolicyType+"|sandbox/ns/shared") == nil {
		t.Fatal("same-name sources collided")
	}
	update := func(raw string) {
		t.Helper()
		updated := sandbox.DeepCopy()
		updated.Annotations[sandboxSecurityRulesAnnotation] = raw
		sandbox, err = metadata.UpdateFake(updated, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	update(rules("updated.example.com"))
	check("updated.example.com")
	update(`[invalid`)
	check("updated.example.com")
	update(rules("recovered.example.com"))
	check("recovered.example.com")
	update(`[{"match":[{"domains":["plain.example.com"],"schemes":["http"]}]}]`)
	check("")
	update(rules("restored.example.com"))
	check("restored.example.com")
	update("")
	check("")
	update(rules("deleted.example.com"))
	check("deleted.example.com")
	if err := metadata.Delete(test.NewContext(t), sandbox.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	check("")
	if inline.GetKey(other.ResourceName()).Policy != untouched {
		t.Fatal("Sandbox churn rebuilt an unrelated Pod's SNI payload")
	}
	profiles.DeleteObject("ns/shared")
	retry.UntilSuccessOrFail(t, func() error {
		if len(inline.List()) != 0 {
			return fmt.Errorf("SNI payloads survived removal of all sources")
		}
		return nil
	})
}

func TestSandboxSNIPolicyFollowsSystemProfiles(t *testing.T) {
	for _, priority := range []int32{0, agentsv1alpha1.DefaultSecurityProfilePriority, math.MaxInt32} {
		t.Run(fmt.Sprint(priority), func(t *testing.T) {
			stop := test.NewStop(t)
			opts := krt.NewOptionsBuilder(stop, "sandbox-sni-order", krt.GlobalDebugHandler)
			// The Sandbox's earlier creation time and name would win a priority tie.
			sandbox := sniTestSandbox("ns", "aaa-sandbox", `[{"name":"r","match":[{"domains":["sandbox.example.com"]}],"actions":{"block":{}}}]`)
			sandbox.CreationTimestamp = metav1.Unix(1, 0)
			policy, err := bindablePolicyFromSandbox(sandbox)
			if err != nil || policy == nil {
				t.Fatalf("Sandbox policy = %v, %v", policy, err)
			}
			metadata := metav1.ObjectMeta{Name: "system", CreationTimestamp: metav1.Unix(2, 0)}
			spec := func(domain string) agentsv1alpha1.SecurityProfileSpec {
				return agentsv1alpha1.SecurityProfileSpec{Priority: ptr.To(priority), Rules: []agentsv1alpha1.SecurityRule{{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}}}}}
			}
			global, err := bindablePolicyFromGlobalSecurityProfile(&agentsv1alpha1.GlobalSecurityProfile{ObjectMeta: metadata, Spec: spec("global.example.com")})
			if err != nil || global == nil {
				t.Fatalf("global policy = %v, %v", global, err)
			}
			metadata.Namespace = "ns"
			namespaced, err := bindablePolicyFromSecurityProfile(&agentsv1alpha1.SecurityProfile{ObjectMeta: metadata, Spec: spec("namespaced.example.com")})
			if err != nil || namespaced == nil {
				t.Fatalf("namespaced policy = %v, %v", namespaced, err)
			}
			policies := krt.NewStaticCollection(nil, []BindablePolicy{*policy, *namespaced, *global}, opts.WithName("policies")...)
			workload := sniTestWorkload(sandbox.Name, sandbox.Namespace, nil)
			workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{workload}, opts.WithName("workloads")...)
			controller := &Controller{bindablePolicies: policies, policyAttachments: newPolicyAttachmentsCollection(policies, opts)}
			inline := controller.BuildWorkloadSNIPoliciesCollection(workloads, opts)
			if !inline.WaitUntilSynced(stop) {
				t.Fatal("SNI payload collection did not sync")
			}
			want := &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
				sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "global.example.com"),
				sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "namespaced.example.com"),
				sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "sandbox.example.com"),
			}}
			retry.UntilSuccessOrFail(t, func() error {
				got := inline.GetKey(workload.ResourceName())
				if got == nil || !proto.Equal(got.Policy, want) {
					return fmt.Errorf("policy = %v, want system profiles followed by Sandbox: %v", got, want)
				}
				return nil
			})
		})
	}
}
