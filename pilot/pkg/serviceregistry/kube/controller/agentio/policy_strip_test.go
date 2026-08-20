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
	"reflect"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/api/annotation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestStripTrafficPolicyUnusedFields(t *testing.T) {
	from := make([]agentsv1alpha1.TrafficPolicyPeer, 1, 8)
	from[0] = agentsv1alpha1.TrafficPolicyPeer{
		Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
			Namespace: "source",
			Selector:  map[string]string{"app": "client"},
		},
	}
	to := make([]agentsv1alpha1.TrafficPolicyPeer, 2, 8)
	to[0] = agentsv1alpha1.TrafficPolicyPeer{FQDN: "api.example.com"}
	to[1] = agentsv1alpha1.TrafficPolicyPeer{
		Service: &agentsv1alpha1.TrafficPolicyServiceRef{Name: "backend", Namespace: "server"},
	}
	ports := make([]agentsv1alpha1.TrafficPolicyPort, 1, 8)
	port := int32(443)
	ports[0] = agentsv1alpha1.TrafficPolicyPort{Protocol: "TCP", Port: &port}
	rules := make([]agentsv1alpha1.TrafficPolicyRule, 1, 8)
	rules[0] = agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		From:   from,
		To:     to,
		Ports:  ports,
	}
	values := make([]string, 1, 8)
	values[0] = "prod"
	expressions := make([]metav1.LabelSelectorRequirement, 1, 8)
	expressions[0] = metav1.LabelSelectorRequirement{
		Key: "environment", Operator: metav1.LabelSelectorOpIn, Values: values,
	}

	policy := &agentsv1alpha1.TrafficPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "agents.kruise.io/v1alpha1", Kind: "TrafficPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "allow-api",
			Namespace:       "sandbox",
			UID:             types.UID("uid"),
			ResourceVersion: "42",
			Generation:      7,
			Labels:          map[string]string{"unused": "label"},
			Annotations: map[string]string{
				annotation.IoIstioDryRun.Name: "true",
				"unused":                      "annotation",
			},
			Finalizers:      []string{"unused"},
			OwnerReferences: []metav1.OwnerReference{{Name: "unused"}},
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "test"}},
		},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 17,
			Selector: metav1.LabelSelector{
				MatchLabels:      map[string]string{"app": "agent"},
				MatchExpressions: expressions,
			},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: rules},
		},
		Status: agentsv1alpha1.TrafficPolicyStatus{
			Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}},
		},
	}
	wantSpec := policy.Spec.DeepCopy()
	wantEgress := policy.Spec.Egress

	got, err := stripTrafficPolicyUnusedFields(policy)
	if err != nil {
		t.Fatalf("stripTrafficPolicyUnusedFields() error = %v", err)
	}
	if got != policy {
		t.Fatalf("stripTrafficPolicyUnusedFields() returned %p, want original %p", got, policy)
	}
	if !reflect.DeepEqual(policy.Spec, *wantSpec) {
		t.Fatalf("retained spec changed: got %+v, want %+v", policy.Spec, *wantSpec)
	}
	if policy.Spec.Egress != wantEgress {
		t.Fatal("TrafficPolicy spec was copied instead of being preserved as-is")
	}
	if policy.Name != "allow-api" || policy.Namespace != "sandbox" || policy.UID != "uid" ||
		policy.ResourceVersion != "42" || policy.Generation != 7 {
		t.Fatalf("required metadata changed: %+v", policy.ObjectMeta)
	}
	if !reflect.DeepEqual(policy.Annotations, map[string]string{annotation.IoIstioDryRun.Name: "true"}) {
		t.Fatalf("annotations = %v, want only dry-run annotation", policy.Annotations)
	}
	if policy.Labels != nil || policy.Finalizers != nil || policy.OwnerReferences != nil || policy.ManagedFields != nil {
		t.Fatalf("unused metadata was not stripped: %+v", policy.ObjectMeta)
	}
	if len(policy.Status.Conditions) != 0 {
		t.Fatalf("status was not stripped: %+v", policy.Status)
	}
}

func TestStripSecurityProfileUnusedFields(t *testing.T) {
	priority := int32(23)
	created := metav1.NewTime(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC))
	domains := make([]string, 2, 16)
	domains[0], domains[1] = "api.example.com", "*.example.com"
	schemes := make([]string, 1, 8)
	schemes[0] = "https"
	matches := make([]agentsv1alpha1.RuleMatch, 1, 8)
	matches[0] = agentsv1alpha1.RuleMatch{
		Domains:     domains,
		Schemes:     schemes,
		Paths:       []agentsv1alpha1.PathMatch{{Type: agentsv1alpha1.PathMatchTypePrefix, Value: "/api"}},
		Methods:     []string{"POST"},
		Ports:       []int32{443},
		Headers:     []agentsv1alpha1.HeaderMatch{{Name: "authorization", Value: "secret"}},
		QueryParams: []agentsv1alpha1.QueryParamMatch{{Name: "token", Value: "secret"}},
	}
	rules := make([]agentsv1alpha1.SecurityRule, 1, 8)
	rules[0] = agentsv1alpha1.SecurityRule{
		Name:    "terminate-api",
		Match:   matches,
		Actions: agentsv1alpha1.SecurityRuleActions{Block: &agentsv1alpha1.BlockAction{StatusCode: 403}},
	}
	profile := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "api",
			Namespace:         "sandbox",
			CreationTimestamp: created,
			ResourceVersion:   "9",
			Generation:        3,
			Labels:            map[string]string{"unused": "label"},
			Annotations:       map[string]string{"unused": "annotation"},
			Finalizers:        []string{"unused"},
			OwnerReferences:   []metav1.OwnerReference{{Name: "unused"}},
			ManagedFields:     []metav1.ManagedFieldsEntry{{Manager: "test"}},
		},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			Priority: &priority,
			Inputs: []agentsv1alpha1.SecurityProfileInput{{
				Name: "credentials", Inline: map[string]string{"token": "secret"},
			}},
			Rules: rules,
			Audit: []agentsv1alpha1.AuditAction{{Name: "audit"}},
		},
		Status: agentsv1alpha1.SecurityProfileStatus{
			ObservedGeneration: 3,
			Conditions:         []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}},
		},
	}
	wantSpec := profile.Spec.DeepCopy()
	wantRules := &profile.Spec.Rules[0]
	wantPolicy, err := bindablePolicyFromSecurityProfile(profile)
	if err != nil {
		t.Fatalf("bindablePolicyFromSecurityProfile() before strip error = %v", err)
	}

	got, err := stripSecurityProfileUnusedFields(profile)
	if err != nil {
		t.Fatalf("stripSecurityProfileUnusedFields() error = %v", err)
	}
	if got != profile {
		t.Fatalf("stripSecurityProfileUnusedFields() returned %p, want original %p", got, profile)
	}
	afterPolicy, err := bindablePolicyFromSecurityProfile(profile)
	if err != nil {
		t.Fatalf("bindablePolicyFromSecurityProfile() after strip error = %v", err)
	}
	if wantPolicy == nil || afterPolicy == nil || !wantPolicy.Equals(*afterPolicy) {
		t.Fatalf("derived SNI policy changed after strip: before=%+v after=%+v", wantPolicy, afterPolicy)
	}
	if !reflect.DeepEqual(profile.Spec, *wantSpec) {
		t.Fatalf("retained spec changed: got %+v, want %+v", profile.Spec, *wantSpec)
	}
	if &profile.Spec.Rules[0] != wantRules {
		t.Fatal("SecurityProfile spec was copied instead of being preserved as-is")
	}
	if profile.Name != "api" || profile.Namespace != "sandbox" || !profile.CreationTimestamp.Equal(&created) ||
		profile.ResourceVersion != "9" || profile.Generation != 3 {
		t.Fatalf("required metadata changed: %+v", profile.ObjectMeta)
	}
	if profile.Labels != nil || profile.Annotations != nil || profile.Finalizers != nil ||
		profile.OwnerReferences != nil || profile.ManagedFields != nil {
		t.Fatalf("unused metadata was not stripped: %+v", profile.ObjectMeta)
	}
	match := profile.Spec.Rules[0].Match[0]
	if !reflect.DeepEqual(match.Domains, []string{"api.example.com", "*.example.com"}) ||
		!reflect.DeepEqual(match.Schemes, []string{"https"}) {
		t.Fatalf("required SNI match fields changed: %+v", match)
	}
	if profile.Status.ObservedGeneration != 0 || len(profile.Status.Conditions) != 0 {
		t.Fatalf("status was not stripped: %+v", profile.Status)
	}
}

func TestStripPolicyUnusedFieldsSupportsGlobalPolicies(t *testing.T) {
	traffic := &agentsv1alpha1.GlobalTrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "global-traffic", Labels: map[string]string{"unused": "label"}},
		Status: agentsv1alpha1.TrafficPolicyStatus{
			Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}},
		},
	}
	security := &agentsv1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "global-security", Annotations: map[string]string{"unused": "annotation"}},
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"global.example.com"}}},
		}}},
		Status: agentsv1alpha1.SecurityProfileStatus{ObservedGeneration: 1},
	}

	if _, err := stripTrafficPolicyUnusedFields(traffic); err != nil {
		t.Fatalf("strip global TrafficPolicy error = %v", err)
	}
	if _, err := stripSecurityProfileUnusedFields(security); err != nil {
		t.Fatalf("strip global SecurityProfile error = %v", err)
	}
	if traffic.Name != "global-traffic" || traffic.Labels != nil || len(traffic.Status.Conditions) != 0 {
		t.Fatalf("global TrafficPolicy not stripped as expected: %+v", traffic)
	}
	if security.Name != "global-security" || security.Annotations != nil || security.Status.ObservedGeneration != 0 ||
		security.Spec.Rules[0].Name != "rule" || !reflect.DeepEqual(security.Spec.Rules[0].Match[0].Domains, []string{"global.example.com"}) {
		t.Fatalf("global SecurityProfile not stripped as expected: %+v", security)
	}
}
