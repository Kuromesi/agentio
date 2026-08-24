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
	"reflect"
	"strings"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func TestBindablePolicyFromSecurityProfile(t *testing.T) {
	priority := int32(17)
	created := metav1.NewTime(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC))
	profile := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ordered", Namespace: "sandbox", CreationTimestamp: created},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Priority: &priority,
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "environment",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"prod", "staging"},
				}},
			},
			Rules: []agentsv1alpha1.SecurityRule{
				{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"API.Example.COM.", "*.Example.com"}}}},
				{Match: []agentsv1alpha1.RuleMatch{{
					Domains: []string{"api.example.com", "*"},
					Schemes: []string{"HTTP", "HTTPS"},
				}}},
				{Match: []agentsv1alpha1.RuleMatch{{
					Domains: []string{"plain.example.com"},
					Schemes: []string{"http"},
				}}},
			},
		},
	}

	got, err := bindablePolicyFromSecurityProfile(profile)
	if err != nil {
		t.Fatalf("bindablePolicyFromSecurityProfile() error = %v", err)
	}
	if got == nil {
		t.Fatal("bindablePolicyFromSecurityProfile() = nil, want policy")
	}
	if got.Name != "sandbox/ordered" || got.TypeURL != xdsmodel.SniTrafficPolicyType ||
		got.ConfigKind != kind.SniTrafficPolicy || got.Namespace != "sandbox" || got.Priority != -17 {
		t.Fatalf("unexpected bindable policy metadata: %+v", got)
	}
	if !got.CreationTime.Equal(created.Time) || got.SourceName != "ordered" || got.SourceNamespace != "sandbox" {
		t.Fatalf("unexpected source ordering metadata: %+v", got)
	}
	if !reflect.DeepEqual(got.Selector, profile.Spec.Selector) {
		t.Fatalf("selector = %v, want app=agent", got.Selector)
	}
	if got.ResourceName() != xdsmodel.SniTrafficPolicyType+"|sandbox/ordered" {
		t.Fatalf("internal resource name = %q", got.ResourceName())
	}
	if got.ConfigKey().Name != "sandbox/ordered" || got.ConfigKey().Namespace != "" {
		t.Fatalf("ConfigKey() = %+v", got.ConfigKey())
	}

	resource, ok := got.Resource.(*extensions.SniTrafficPolicy)
	if !ok {
		t.Fatalf("resource type = %T, want *extensions.SniTrafficPolicy", got.Resource)
	}
	wantHosts := []string{"api.example.com", "*.example.com", "*"}
	if hosts := resource.GetRules()[0].GetMatch().GetSni(); !reflect.DeepEqual(hosts, wantHosts) {
		t.Fatalf("hosts = %v, want %v", hosts, wantHosts)
	}

	profile.Spec.Selector.MatchLabels["app"] = "mutated"
	profile.Spec.Selector.MatchExpressions[0].Values[0] = "mutated"
	if got.Selector.MatchLabels["app"] != "agent" || got.Selector.MatchExpressions[0].Values[0] != "prod" {
		t.Fatalf("derived selector aliases SecurityProfile: %+v", got)
	}
}

func TestBindablePolicyFromGlobalSecurityProfile(t *testing.T) {
	priority := int32(7)
	profile := &agentsv1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "global"},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Priority: &priority,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"Global.Example.com."}, Schemes: []string{"https"}}},
			}},
		},
	}

	got, err := bindablePolicyFromGlobalSecurityProfile(profile)
	if err != nil {
		t.Fatalf("bindablePolicyFromGlobalSecurityProfile() error = %v", err)
	}
	if got == nil {
		t.Fatal("bindablePolicyFromGlobalSecurityProfile() = nil, want policy")
	}
	if got.Name != "global" || got.Namespace != "" || got.Priority != -7 {
		t.Fatalf("unexpected global bindable policy metadata: %+v", got)
	}
	if got.ResourceName() != xdsmodel.SniTrafficPolicyType+"|global" {
		t.Fatalf("internal resource name = %q", got.ResourceName())
	}
	if !got.Selects("ns-a", map[string]string{"app": "agent"}) ||
		!got.Selects("ns-b", map[string]string{"app": "agent"}) {
		t.Fatal("global profile must select matching workloads across namespaces")
	}
	if got.Selects("ns-a", map[string]string{"app": "other"}) {
		t.Fatal("global profile selected workload with mismatched labels")
	}
	resource := got.Resource.(*extensions.SniTrafficPolicy)
	if hosts := resource.GetRules()[0].GetMatch().GetSni(); !reflect.DeepEqual(hosts, []string{"global.example.com"}) {
		t.Fatalf("hosts = %v, want [global.example.com]", hosts)
	}
}

func TestBindablePolicyFromSecurityProfileDefaultsAndSkipsNonHTTPS(t *testing.T) {
	profile := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "defaults", Namespace: "sandbox"},
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"Default.Example.com."}}},
		}}},
	}
	got, err := bindablePolicyFromSecurityProfile(profile)
	if err != nil || got == nil {
		t.Fatalf("bindablePolicyFromSecurityProfile() = (%+v, %v), want policy", got, err)
	}
	if got.Priority != -agentsv1alpha1.DefaultSecurityProfilePriority {
		t.Fatalf("priority = %d, want %d", got.Priority, -agentsv1alpha1.DefaultSecurityProfilePriority)
	}
	resource := got.Resource.(*extensions.SniTrafficPolicy)
	if hosts := resource.GetRules()[0].GetMatch().GetSni(); !reflect.DeepEqual(hosts, []string{"default.example.com"}) {
		t.Fatalf("hosts = %v, want [default.example.com]", hosts)
	}

	profile.Spec.Rules[0].Match[0].Schemes = []string{"http", "ws"}
	got, err = bindablePolicyFromSecurityProfile(profile)
	if err != nil || got != nil {
		t.Fatalf("non-HTTPS profile = (%+v, %v), want (nil, nil)", got, err)
	}
}

func TestBindablePolicyFromSecurityProfileRejectsInvalidInput(t *testing.T) {
	negativePriority := int32(-1)
	tests := []struct {
		name    string
		profile *agentsv1alpha1.SecurityProfile
		wantErr string
	}{
		{name: "nil profile", wantErr: "SecurityProfile is nil"},
		{
			name: "invalid selector",
			profile: &agentsv1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-selector", Namespace: "sandbox"},
				Spec: agentsv1alpha1.SecurityProfileSpec{Selector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key: "app", Operator: metav1.LabelSelectorOperator("Unknown"),
					}},
				}},
			},
			wantErr: "invalid selector",
		},
		{
			name: "negative priority",
			profile: &agentsv1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "negative", Namespace: "sandbox"},
				Spec:       agentsv1alpha1.SecurityProfileSpec{Priority: &negativePriority},
			},
			wantErr: "negative priority -1",
		},
		{
			name: "invalid host",
			profile: &agentsv1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-host", Namespace: "sandbox"},
				Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"valid.example.com", "*foo.example.com"}}},
				}}},
			},
			wantErr: "domains[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bindablePolicyFromSecurityProfile(tt.profile)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if got != nil {
				t.Fatalf("policy = %+v, want nil", got)
			}
		})
	}
}

func TestBindablePoliciesFromSecurityProfilesLifecycle(t *testing.T) {
	newProfile := func(name, namespace, domain string) *agentsv1alpha1.SecurityProfile {
		return &agentsv1alpha1.SecurityProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}, Schemes: []string{"https"}}},
			}}},
		}
	}
	newGlobalProfile := func(name, domain string) *agentsv1alpha1.GlobalSecurityProfile {
		return &agentsv1alpha1.GlobalSecurityProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}, Schemes: []string{"https"}}},
			}}},
		}
	}

	agentsCS := agentsfake.NewSimpleClientset(
		newProfile("existing", "ns-a", "Initial.Example.com."),
		newGlobalProfile("global-existing", "Global-Initial.Example.com."),
	)
	registerSecurityProfileType(agentsCS)
	registerGlobalSecurityProfileType(agentsCS)
	client := kube.NewFakeClient()
	clienttest.MakeCRD(t, client, securityProfileGVR)
	clienttest.MakeCRD(t, client, globalSecurityProfileGVR)
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "bindable-policy-test", krt.GlobalDebugHandler)
	profiles := newSecurityProfilesCollection(client, stop, opts)
	globalProfiles := newGlobalSecurityProfilesCollection(client, stop, opts)
	policies := newBindablePoliciesCollection(profiles, globalProfiles, opts)
	client.RunAndWait(stop)
	if !policies.WaitUntilSynced(stop) {
		t.Fatal("BindablePolicies never synced")
	}

	assertPolicy := func(key, wantHost string) error {
		policy := policies.GetKey(xdsmodel.SniTrafficPolicyType + "|" + key)
		if policy == nil {
			return fmt.Errorf("policy %s not found", key)
		}
		resource := policy.Resource.(*extensions.SniTrafficPolicy)
		hosts := resource.GetRules()[0].GetMatch().GetSni()
		if !reflect.DeepEqual(hosts, []string{wantHost}) {
			return fmt.Errorf("policy %s hosts = %v, want [%s]", key, hosts, wantHost)
		}
		return nil
	}

	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("ns-a/existing", "initial.example.com")
	}, retry.Timeout(5*time.Second))
	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("global-existing", "global-initial.example.com")
	}, retry.Timeout(5*time.Second))

	ctx := test.NewContext(t)
	live, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Create(
		ctx, newProfile("live", "ns-b", "Live.Example.com."), metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("ns-b/live", "live.example.com")
	}, retry.Timeout(5*time.Second))

	live.Spec.Rules[0].Match[0].Domains = []string{"Updated.Example.com."}
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Update(ctx, live, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("ns-b/live", "updated.example.com")
	}, retry.Timeout(5*time.Second))

	globalLive, err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Create(
		ctx, newGlobalProfile("global-live", "Global-Live.Example.com."), metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("global-live", "global-live.example.com")
	}, retry.Timeout(5*time.Second))

	globalLive.Spec.Rules[0].Match[0].Domains = []string{"Global-Updated.Example.com."}
	if _, err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Update(ctx, globalLive, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		return assertPolicy("global-live", "global-updated.example.com")
	}, retry.Timeout(5*time.Second))

	if err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-a").Delete(ctx, "existing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		if policy := policies.GetKey(xdsmodel.SniTrafficPolicyType + "|ns-a/existing"); policy != nil {
			return fmt.Errorf("deleted policy still present: %+v", policy)
		}
		return nil
	}, retry.Timeout(5*time.Second))

	if err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Delete(ctx, "global-existing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		if policy := policies.GetKey(xdsmodel.SniTrafficPolicyType + "|global-existing"); policy != nil {
			return fmt.Errorf("deleted global policy still present: %+v", policy)
		}
		return nil
	}, retry.Timeout(5*time.Second))
}

func TestBindablePolicyEqualsAndSelects(t *testing.T) {
	policy := func(selector map[string]string) BindablePolicy {
		return BindablePolicy{
			Name:       "ns/p",
			TypeURL:    xdsmodel.SniTrafficPolicyType,
			ConfigKind: kind.SniTrafficPolicy,
			Namespace:  "ns",
			Priority:   2,
			Selector:   metav1.LabelSelector{MatchLabels: selector},
			Resource: &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
				sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "example.com"),
			}},
		}
	}
	a, b := policy(map[string]string{"app": "agent"}), policy(map[string]string{"app": "agent"})
	if !a.Equals(b) || !b.Equals(a) {
		t.Fatal("structurally identical bindable policies must be equal")
	}
	b.Priority++
	if a.Equals(b) {
		t.Fatal("different priorities must not be equal")
	}
	b = a
	b.CreationTime = time.Unix(1, 0)
	if a.Equals(b) {
		t.Fatal("different source creation times must not be equal")
	}

	if !a.Selects("ns", map[string]string{"app": "agent", "extra": "x"}) {
		t.Fatal("matching selector did not select workload")
	}
	if a.Selects("ns", map[string]string{"app": "other"}) || a.Selects("other", map[string]string{"app": "agent"}) {
		t.Fatal("selector matched the wrong workload")
	}
	empty := policy(nil)
	if !empty.Selects("ns", nil) || empty.Selects("other", nil) {
		t.Fatal("empty selector must match only its own namespace")
	}
	global := policy(map[string]string{"app": "agent"})
	global.Name = "global"
	global.Namespace = ""
	if !global.Selects("ns", map[string]string{"app": "agent"}) ||
		!global.Selects("other", map[string]string{"app": "agent"}) {
		t.Fatal("empty policy namespace must select matching workloads in every namespace")
	}
}

func TestBindablePoliciesDisabled(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, false)
	c := &Controller{}
	c.initBindablePolicies(krttest.Options(t))
	if c.BindablePolicies() != nil {
		t.Errorf("BindablePolicies() = %v, want nil", c.BindablePolicies())
	}
	if got := c.BuildWorkloadPolicyReferencesCollection(nil, krttest.Options(t)); got != nil {
		t.Errorf("BuildWorkloadPolicyReferencesCollection() = %v, want nil", got)
	}
	if c.WorkloadPolicyReferences() != nil {
		t.Errorf("WorkloadPolicyReferences() = %v, want nil", c.WorkloadPolicyReferences())
	}
}

func TestControllerDoesNotWatchSniPolicySourcesWhenDisabled(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, false)
	c, err := NewController(Options{
		KubeClient: kube.NewFakeClient(),
		MeshConfig: meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{RootNamespace: "istio-system"}),
		Stop:       test.NewStop(t),
	})
	if err != nil {
		t.Fatalf("NewController() failed: %v", err)
	}
	if c.securityProfiles != nil || c.globalSecurityProfiles != nil {
		t.Fatalf("disabled SNI policy sources = (%v, %v), want both nil", c.securityProfiles, c.globalSecurityProfiles)
	}
}
