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
	"sort"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/api/security/v1beta1"
	securityclient "istio.io/client-go/pkg/apis/security/v1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	"istio.io/istio/pkg/workloadapi/security"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeTransform mirrors the production toAuthorizationPolicy callback wired in
// by ambient: it always returns a successfully bound Authorization with the
// AuthorizationPolicy's name/namespace, so the test can assert on the
// downstream WorkloadAuthorization structure produced by the controller.
func fakeTransform(ap *securityclient.AuthorizationPolicy) (*security.Authorization, *model.StatusMessage) {
	return &security.Authorization{
		Name:      ap.Name,
		Namespace: ap.Namespace,
		Scope:     security.Scope_NAMESPACE,
	}, nil
}

// fakeResolver returns a deterministic IP list for a given FQDN so tests can
// exercise the FQDN branch of convertRule without going through DNS.
func fakeResolver(_ krt.HandlerContext, host string) []string {
	switch host {
	case "example.com":
		return []string{"203.0.113.10", "203.0.113.11"}
	default:
		return nil
	}
}

func newControllerForTest(t *testing.T, services []*corev1.Service, endpointSlices []*discovery.EndpointSlice, pods []*corev1.Pod) *authorizationController {
	t.Helper()
	inputs := make([]any, 0, len(services)+len(endpointSlices)+len(pods))
	for _, s := range services {
		inputs = append(inputs, s)
	}
	for _, es := range endpointSlices {
		inputs = append(inputs, es)
	}
	for _, p := range pods {
		inputs = append(inputs, p)
	}
	mock := krttest.NewMock(t, inputs)
	svcCol := krttest.GetMockCollection[*corev1.Service](mock)
	esCol := krttest.GetMockCollection[*discovery.EndpointSlice](mock)
	podCol := krttest.GetMockCollection[*corev1.Pod](mock)
	tpCol := krttest.GetMockCollection[*agentsv1alpha1.TrafficPolicy](mock)
	gtpCol := krttest.GetMockCollection[*agentsv1alpha1.GlobalTrafficPolicy](mock)
	return newAuthorizationController(tpCol, gtpCol, svcCol, esCol, fakeResolver, podCol, fakeTransform, "istio-system")
}

func podWith(name, ns string, labels map[string]string, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Status: corev1.PodStatus{
			PodIP:  ip,
			PodIPs: []corev1.PodIP{{IP: ip}},
		},
	}
}

func svcWith(name, ns, clusterIP string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			ClusterIP: clusterIP,
			Selector:  selector,
		},
	}
}

func findCondition(rule *v1beta1.Rule, key string) *v1beta1.Condition {
	for _, c := range rule.When {
		if c.Key == key {
			return c
		}
	}
	return nil
}

func sortStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestConvertRule_CIDRAllow(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	port := int32(8080)
	endPort := int32(8090)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
		Ports:  []agentsv1alpha1.TrafficPolicyPort{{Port: &port, EndPort: &endPort}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)

	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.Values) != 1 || dst.Values[0] != "10.0.0.0/24" {
		t.Errorf("expected destination.ip=[10.0.0.0/24], got %+v", dst)
	}
	if dst.NotValues != nil {
		t.Errorf("expected allow → Values populated, NotValues empty; got %+v", dst.NotValues)
	}
	ports := findCondition(got, "destination.portRange")
	if ports == nil || len(ports.Values) != 1 || ports.Values[0] != "8080-8090" {
		t.Errorf("expected destination.portRange=[8080-8090], got %+v", ports)
	}
}

func TestConvertRule_CIDRDeny_UsesNotValues(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionReject,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.NotValues) != 1 || dst.NotValues[0] != "10.0.0.0/24" {
		t.Errorf("expected deny → NotValues populated; got %+v", dst)
	}
	if dst.Values != nil {
		t.Errorf("deny should not populate Values; got %+v", dst.Values)
	}
}

func TestConvertRule_PortRangeFormatting(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	startOnly := int32(8000)
	endOnly := int32(9000)
	cases := []struct {
		name  string
		port  agentsv1alpha1.TrafficPolicyPort
		want  string // empty means no portRange condition expected
		empty bool
	}{
		{"start only", agentsv1alpha1.TrafficPolicyPort{Port: &startOnly}, "8000-", false},
		{"end only", agentsv1alpha1.TrafficPolicyPort{EndPort: &endOnly}, "-9000", false},
		{"range with protocol", agentsv1alpha1.TrafficPolicyPort{Protocol: "TCP", Port: &startOnly, EndPort: &endOnly}, "8000-9000/TCP", false},
		{"protocol only", agentsv1alpha1.TrafficPolicyPort{Protocol: "UDP"}, "/UDP", false},
		{"both nil skips port", agentsv1alpha1.TrafficPolicyPort{}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := agentsv1alpha1.TrafficPolicyRule{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}},
				Ports:  []agentsv1alpha1.TrafficPolicyPort{tc.port},
			}
			got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
			ports := findCondition(got, "destination.portRange")
			if tc.empty {
				if ports != nil {
					t.Errorf("expected no portRange condition, got %+v", ports)
				}
				return
			}
			if ports == nil || len(ports.Values) != 1 || ports.Values[0] != tc.want {
				t.Errorf("expected portRange=[%s], got %+v", tc.want, ports)
			}
		})
	}
}

func TestConvertRule_FQDNResolver(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "example.com"}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	want := []string{"203.0.113.10", "203.0.113.11"}
	if dst == nil || len(dst.Values) != 2 {
		t.Fatalf("expected 2 resolved IPs, got %+v", dst)
	}
	if got, want := sortStrings(dst.Values), sortStrings(want); got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestConvertRule_UnresolvedPeerAddsNeverMatchCondition(t *testing.T) {
	tests := []struct {
		name   string
		action agentsv1alpha1.RuleAction
		peer   agentsv1alpha1.TrafficPolicyPeer
	}{
		{
			name:   "allow FQDN",
			action: agentsv1alpha1.RuleActionAllow,
			peer:   agentsv1alpha1.TrafficPolicyPeer{FQDN: "unknown.invalid"},
		},
		{
			name:   "reject FQDN",
			action: agentsv1alpha1.RuleActionReject,
			peer:   agentsv1alpha1.TrafficPolicyPeer{FQDN: "unknown.invalid"},
		},
		{
			name:   "allow workload",
			action: agentsv1alpha1.RuleActionAllow,
			peer: agentsv1alpha1.TrafficPolicyPeer{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
				Namespace: "default",
				Selector:  map[string]string{"app": "missing"},
			}},
		},
		{
			name:   "reject workload",
			action: agentsv1alpha1.RuleActionReject,
			peer: agentsv1alpha1.TrafficPolicyPeer{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
				Namespace: "default",
				Selector:  map[string]string{"app": "missing"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newControllerForTest(t, nil, nil, nil)
			rule := agentsv1alpha1.TrafficPolicyRule{
				Action: tt.action,
				To:     []agentsv1alpha1.TrafficPolicyPeer{tt.peer},
			}
			got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
			dst := findCondition(got, "destination.ip")
			if dst == nil || len(dst.Values) != 0 || len(dst.NotValues) != 0 {
				t.Errorf("expected empty destination.ip condition, got %+v", dst)
			}
		})
	}
}

func TestConvertRule_UnresolvedFromAddsNeverMatchCondition(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		From:   []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "unknown.invalid"}},
	}

	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	src := findCondition(got, "source.ip")
	if src == nil || len(src.Values) != 0 || len(src.NotValues) != 0 {
		t.Errorf("expected empty source.ip condition, got %+v", src)
	}
}

func TestConvertRule_InvalidCIDRIsKeptForNeverMatchCompilation(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "not-a-cidr"}},
	}

	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.Values) != 1 || dst.Values[0] != "not-a-cidr" {
		t.Errorf("expected invalid CIDR condition to reach never-match compilation, got %+v", dst)
	}
}

func TestConvertRule_ResolvedPeerPreservesORWithUnresolvedPeer(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{
			{FQDN: "unknown.invalid"},
			{CIDR: "10.0.0.0/24"},
		},
	}

	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.Values) != 1 || dst.Values[0] != "10.0.0.0/24" {
		t.Errorf("expected the resolved peer to remain as the only OR candidate, got %+v", dst)
	}
}

func TestConvertRule_OmittedPeerRemainsWildcard(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	got := c.convertRule(krt.TestingDummyContext{}, agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
	}, "default", fakeResolver)

	if src := findCondition(got, "source.ip"); src != nil {
		t.Errorf("expected omitted from to remain wildcard, got %+v", src)
	}
	if dst := findCondition(got, "destination.ip"); dst != nil {
		t.Errorf("expected omitted to to remain wildcard, got %+v", dst)
	}
}

func TestConvertRule_UnresolvedPeerRemainsANDedWithPorts(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	port := int32(443)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "unknown.invalid"}},
		Ports:  []agentsv1alpha1.TrafficPolicyPort{{Port: &port}},
	}

	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	if len(got.When) != 2 {
		t.Fatalf("expected peer and port to produce two ANDed conditions, got %+v", got.When)
	}
	if dst := findCondition(got, "destination.ip"); dst == nil || len(dst.Values) != 0 || len(dst.NotValues) != 0 {
		t.Errorf("expected empty destination.ip condition, got %+v", dst)
	}
	if ports := findCondition(got, "destination.portRange"); ports == nil || len(ports.Values) != 1 || ports.Values[0] != "443-" {
		t.Errorf("expected destination.portRange=[443-], got %+v", ports)
	}
}

func TestConvertRule_SrcAndDstBothPopulated(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		From:   []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.168.0.0/16"}},
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	if src := findCondition(got, "source.ip"); src == nil || src.Values[0] != "192.168.0.0/16" {
		t.Errorf("expected source.ip set; got %+v", src)
	}
	if dst := findCondition(got, "destination.ip"); dst == nil || dst.Values[0] != "10.0.0.0/24" {
		t.Errorf("expected destination.ip set; got %+v", dst)
	}
}

func TestConvertTrafficPolicyToWorkloadPolicies_EgressOnly(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	tp := agentsv1alpha1.TrafficPolicySpec{
		Priority: 500,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{
				{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
				},
			},
		},
	}
	transform := func(_ krt.HandlerContext, _ metav1.ObjectMeta, _ *agentsv1alpha1.TrafficPolicySpec, ap *securityclient.AuthorizationPolicy) *model.WorkloadAuthorization {
		authz, _ := fakeTransform(ap)
		return &model.WorkloadAuthorization{
			Authorization: authz,
		}
	}
	policies := c.convertTrafficPolicyToWorkloadPolicies(
		krt.TestingDummyContext{},
		metav1.ObjectMeta{Name: "my-pol", Namespace: "ns"},
		&tp,
		"my-pol", "ns",
		fakeResolver,
		transform,
	)
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy (egress only), got %d", len(policies))
	}
	if policies[0].Authorization.Name != "my-pol-egress" {
		t.Errorf("expected name=my-pol-egress, got %s", policies[0].Authorization.Name)
	}
	// Egress branch tags the extension with CLIENT mode.
	if len(policies[0].Authorization.AuthExtensions) == 0 {
		t.Fatalf("expected CLIENT-mode extension appended")
	}
}

func TestConvertTrafficPolicyToWorkloadPolicies_IngressOnly(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	tp := agentsv1alpha1.TrafficPolicySpec{
		Priority: 100,
		Selector: metav1.LabelSelector{},
		Ingress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow}},
		},
	}
	transform := func(_ krt.HandlerContext, _ metav1.ObjectMeta, _ *agentsv1alpha1.TrafficPolicySpec, ap *securityclient.AuthorizationPolicy) *model.WorkloadAuthorization {
		authz, _ := fakeTransform(ap)
		return &model.WorkloadAuthorization{Authorization: authz}
	}
	policies := c.convertTrafficPolicyToWorkloadPolicies(
		krt.TestingDummyContext{},
		metav1.ObjectMeta{Name: "p"},
		&tp, "p", "ns",
		fakeResolver, transform,
	)
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy (ingress only), got %d", len(policies))
	}
	if policies[0].Authorization.Name != "p-ingress" {
		t.Errorf("expected name=p-ingress, got %s", policies[0].Authorization.Name)
	}
}

func TestConvertTrafficPolicyToWorkloadPolicies_Both(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	tp := agentsv1alpha1.TrafficPolicySpec{
		Egress:  &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow}}},
		Ingress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow}}},
	}
	transform := func(_ krt.HandlerContext, _ metav1.ObjectMeta, _ *agentsv1alpha1.TrafficPolicySpec, ap *securityclient.AuthorizationPolicy) *model.WorkloadAuthorization {
		authz, _ := fakeTransform(ap)
		return &model.WorkloadAuthorization{Authorization: authz}
	}
	policies := c.convertTrafficPolicyToWorkloadPolicies(
		krt.TestingDummyContext{},
		metav1.ObjectMeta{Name: "p"},
		&tp, "p", "ns",
		fakeResolver, transform,
	)
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies (egress+ingress), got %d", len(policies))
	}
	// Order is egress then ingress; both must be present.
	names := map[string]bool{}
	for _, p := range policies {
		names[p.Authorization.Name] = true
	}
	for _, want := range []string{"p-egress", "p-ingress"} {
		if !names[want] {
			t.Errorf("expected policy %s in result", want)
		}
	}
}

func TestConvertTrafficPolicyToWorkloadPolicies_Neither(t *testing.T) {
	c := newControllerForTest(t, nil, nil, nil)
	tp := agentsv1alpha1.TrafficPolicySpec{}
	transform := func(_ krt.HandlerContext, _ metav1.ObjectMeta, _ *agentsv1alpha1.TrafficPolicySpec, _ *securityclient.AuthorizationPolicy) *model.WorkloadAuthorization {
		return nil
	}
	policies := c.convertTrafficPolicyToWorkloadPolicies(
		krt.TestingDummyContext{},
		metav1.ObjectMeta{Name: "p"},
		&tp, "p", "ns",
		fakeResolver, transform,
	)
	if len(policies) != 0 {
		t.Errorf("expected empty policies for no egress/ingress, got %d", len(policies))
	}
}

func endpointSliceFor(svcName, ns string, ips ...string) *discovery.EndpointSlice {
	endpoints := make([]discovery.Endpoint, 0, len(ips))
	for _, ip := range ips {
		endpoints = append(endpoints, discovery.Endpoint{
			Addresses: []string{ip},
		})
	}
	return &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName + "-slice",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: svcName},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
}

func TestConvertRule_ServicePeer(t *testing.T) {
	svc := svcWith("frontend", "default", "10.0.0.5", map[string]string{"app": "frontend"})
	es := endpointSliceFor("frontend", "default", "10.244.0.7")
	c := newControllerForTest(t, []*corev1.Service{svc}, []*discovery.EndpointSlice{es}, nil)

	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
			Name: "frontend", Namespace: "default",
		}}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil {
		t.Fatalf("expected destination.ip condition")
	}
	gotIPs := sortStrings(dst.Values)
	want := sortStrings([]string{"10.0.0.5", "10.244.0.7"})
	if len(gotIPs) != len(want) {
		t.Fatalf("expected %v, got %v", want, gotIPs)
	}
	for i := range want {
		if gotIPs[i] != want[i] {
			t.Errorf("at %d: expected %s, got %s", i, want[i], gotIPs[i])
		}
	}
}

func TestConvertRule_ServicePeerDefaultsToPolicyNamespace(t *testing.T) {
	svc := svcWith("frontend", "policy-ns", "10.0.0.5", nil)
	c := newControllerForTest(t, []*corev1.Service{svc}, nil, nil)
	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
			Name: "frontend",
		}}},
	}

	got := c.convertRule(krt.TestingDummyContext{}, rule, "policy-ns", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.Values) != 1 || dst.Values[0] != "10.0.0.5" {
		t.Errorf("expected service lookup in TrafficPolicy namespace, got %+v", dst)
	}
}

func TestConvertRule_ServicePeerWithManualEndpoints(t *testing.T) {
	svc := svcWith("external-db", "default", "10.0.0.10", nil)
	es := endpointSliceFor("external-db", "default", "192.168.1.100", "192.168.1.101")
	c := newControllerForTest(t, []*corev1.Service{svc}, []*discovery.EndpointSlice{es}, nil)

	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
			Name: "external-db", Namespace: "default",
		}}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil {
		t.Fatalf("expected destination.ip condition")
	}
	gotIPs := sortStrings(dst.Values)
	want := sortStrings([]string{"10.0.0.10", "192.168.1.100", "192.168.1.101"})
	if len(gotIPs) != len(want) {
		t.Fatalf("expected %v, got %v", want, gotIPs)
	}
	for i := range want {
		if gotIPs[i] != want[i] {
			t.Errorf("at %d: expected %s, got %s", i, want[i], gotIPs[i])
		}
	}
}

func TestConvertRule_WorkloadPeerSkipsUnreadyPod(t *testing.T) {
	readyPod := podWith("ready", "default", map[string]string{"app": "x"}, "10.244.0.1")
	readyPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	unreadyPod := podWith("unready", "default", map[string]string{"app": "x"}, "10.244.0.2")
	c := newControllerForTest(t, nil, nil, []*corev1.Pod{readyPod, unreadyPod})

	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
			Namespace: "default",
			Selector:  map[string]string{"app": "x"},
		}}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil || len(dst.Values) != 1 || dst.Values[0] != "10.244.0.1" {
		t.Errorf("expected only ready pod IP 10.244.0.1, got %+v", dst)
	}
}

func TestConvertRule_ServicePeerIncludesNotReadyEndpoints(t *testing.T) {
	svc := svcWith("my-svc", "default", "10.0.0.20", nil)
	notReady := false
	es := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc-slice",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "my-svc"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{Addresses: []string{"10.244.0.1"}},
			{Addresses: []string{"10.244.0.2"}, Conditions: discovery.EndpointConditions{Ready: &notReady}},
		},
	}
	c := newControllerForTest(t, []*corev1.Service{svc}, []*discovery.EndpointSlice{es}, nil)

	rule := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To: []agentsv1alpha1.TrafficPolicyPeer{{Service: &agentsv1alpha1.TrafficPolicyServiceRef{
			Name: "my-svc", Namespace: "default",
		}}},
	}
	got := c.convertRule(krt.TestingDummyContext{}, rule, "default", fakeResolver)
	dst := findCondition(got, "destination.ip")
	if dst == nil {
		t.Fatalf("expected destination.ip condition")
	}
	gotIPs := sortStrings(dst.Values)
	want := sortStrings([]string{"10.0.0.20", "10.244.0.1", "10.244.0.2"})
	if len(gotIPs) != len(want) {
		t.Fatalf("expected %v, got %v", want, gotIPs)
	}
	for i := range want {
		if gotIPs[i] != want[i] {
			t.Errorf("at %d: expected %s, got %s", i, want[i], gotIPs[i])
		}
	}
}

// Spot-check: extensions package must export TrafficPolicyMode_CLIENT/SERVER
// used by the conversion logic; this catches accidental enum renames.
var _ = extensions.TrafficPolicyMode_CLIENT
var _ = extensions.TrafficPolicyMode_SERVER
