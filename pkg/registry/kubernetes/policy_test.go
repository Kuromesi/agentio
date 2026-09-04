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
	"context"
	"reflect"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeclient "k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/pkg/kube"
)

func TestAgentioConfigStartsFromDefaults(t *testing.T) {
	ctx := t.Context()
	r := newTestRegistry(t, ctx, nil, nil)

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v, want defaults", config)
	}
	want := []string{
		"agentio.kruise.io/dataplane-mode",
		"pod-template-hash",
		"pod-template-generation",
		"controller-revision-hash",
	}
	if got := config.Value.GetSandboxIgnoredLabels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox ignored labels = %v, want %v", got, want)
	}
}

func TestAgentioConfigMapNamesAreConfigurable(t *testing.T) {
	ctx := t.Context()
	objects := []runtime.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"}, Data: map[string]string{
			"config": "sandboxExtProc:\n  service: ignored.agentio-system.svc.cluster.local\n",
		}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-base"}, Data: map[string]string{
			"config": "sandboxExtProc:\n  service: custom.agentio-system.svc.cluster.local\n  port: 9002\n",
		}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-primary"}, Data: map[string]string{
			"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
		}},
	}
	r := newTestRegistryWithAgentioConfigMaps(t, ctx, objects, nil, &AgentioConfigMapOptions{
		BaseName: "custom-base", PrimaryName: "custom-primary",
	})

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v", config)
	}
	if got := config.Value.GetSandboxExtProc().GetService(); got != "custom.agentio-system.svc.cluster.local" {
		t.Fatalf("sandbox ext-proc service = %q, want custom ConfigMap value", got)
	}
	if got := len(config.Value.GetEgressGateways()); got != 1 {
		t.Fatalf("egress gateways = %d, want primary ConfigMap overlay", got)
	}
}

func TestEmptyPrimaryAgentioConfigMapNameDisablesOverlay(t *testing.T) {
	ctx := t.Context()
	objects := []runtime.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-base"}, Data: map[string]string{
			"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n",
		}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"}, Data: map[string]string{
			"config": "sandboxExtProc:\n  service: must-not-apply.agentio-system.svc.cluster.local\n",
		}},
	}
	r := newTestRegistryWithAgentioConfigMaps(t, ctx, objects, nil, &AgentioConfigMapOptions{
		BaseName: "custom-base", PrimaryName: "",
	})

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v", config)
	}
	if got := config.Value.GetSandboxExtProc().GetService(); got != "base.agentio-system.svc.cluster.local" {
		t.Fatalf("sandbox ext-proc service = %q, want base value with primary disabled", got)
	}
}

func TestAgentioConfigIgnoredLabelsNullPreservesDefaultsAndEmptyClears(t *testing.T) {
	for _, test := range []struct {
		name string
		yaml string
		want []string
	}{
		{name: "null preserves defaults", yaml: "sandboxIgnoredLabels: null", want: defaultAgentioConfiguration().GetSandboxIgnoredLabels()},
		{name: "empty clears defaults", yaml: "sandboxIgnoredLabels: []"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := applyAgentioConfig(test.yaml, defaultAgentioConfiguration())
			if err != nil {
				t.Fatal(err)
			}
			if labels := got.GetSandboxIgnoredLabels(); !reflect.DeepEqual(labels, test.want) {
				t.Fatalf("sandbox ignored labels = %v, want %v", labels, test.want)
			}
		})
	}
}

func TestAgentioConfigPrimaryReplacesFullSubmessage(t *testing.T) {
	for _, test := range []struct {
		name        string
		primary     string
		wantService string
		wantPort    uint32
	}{
		{
			name: "partially specified message resets omitted fields",
			primary: `sandboxExtProc:
  service: primary.agentio-system.svc.cluster.local
`,
			wantService: "primary.agentio-system.svc.cluster.local",
		},
		{
			name: "explicit empty message resets every field", primary: "sandboxExtProc: {}",
		},
		{
			name: "omitted message leaves the lower layer intact", primary: "{}",
			wantService: "base.agentio-system.svc.cluster.local", wantPort: 9002,
		},
		{
			name: "null leaves the lower layer intact", primary: "sandboxExtProc: null",
			wantService: "base.agentio-system.svc.cluster.local", wantPort: 9002,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"}, Data: map[string]string{
				"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n  port: 9002\n",
			}}
			primary := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"}, Data: map[string]string{
				"config": test.primary,
			}}
			r := newTestRegistry(t, ctx, []runtime.Object{base, primary}, nil)

			config := r.AgentioConfig.GetKey("effective")
			if config == nil || config.Value == nil {
				t.Fatalf("effective config = %+v", config)
			}
			extProc := config.Value.GetSandboxExtProc()
			if extProc == nil {
				t.Fatal("sandbox ext-proc is nil")
			}
			if extProc.GetService() != test.wantService || extProc.GetPort() != test.wantPort {
				t.Fatalf("sandbox ext-proc = service %q port %d, want service %q port %d",
					extProc.GetService(), extProc.GetPort(), test.wantService, test.wantPort)
			}
		})
	}
}

func TestApplyAgentioConfigNormalizesStaticServiceEntries(t *testing.T) {
	got, err := applyAgentioConfig(`
egressGateways:
- name: egress
  namespace: agentio-system
  serviceEntries:
  - hosts: [" API.Example.COM. "]
    endpoints:
    - address: " 10.10.20.30 "
    - address: 10.10.20.31
`, nil)
	if err != nil {
		t.Fatalf("applyAgentioConfig(): %v", err)
	}
	entries := got.GetEgressGateways()[0].GetServiceEntries()
	if len(entries) != 1 {
		t.Fatalf("service entries = %d, want 1", len(entries))
	}
	if hosts := entries[0].GetHosts(); !reflect.DeepEqual(hosts, []string{"api.example.com"}) {
		t.Fatalf("hosts = %v, want canonical host", hosts)
	}
	addresses := []string{entries[0].GetEndpoints()[0].GetAddress(), entries[0].GetEndpoints()[1].GetAddress()}
	if !reflect.DeepEqual(addresses, []string{"10.10.20.30", "10.10.20.31"}) {
		t.Fatalf("endpoint addresses = %v, want canonical IPv4 addresses", addresses)
	}
}

func TestApplyAgentioConfigRejectsInvalidStaticServiceEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries string
	}{
		{name: "missing hosts", entries: "- endpoints:\n  - address: 10.10.20.30"},
		{name: "missing endpoints", entries: "- hosts: [api.example.com]"},
		{name: "wildcard host", entries: "- hosts: ['*.example.com']\n  endpoints:\n  - address: 10.10.20.30"},
		{name: "IPv6 endpoint", entries: "- hosts: [api.example.com]\n  endpoints:\n  - address: '2001:db8::1'"},
		{name: "duplicate endpoint", entries: "- hosts: [api.example.com]\n  endpoints:\n  - address: 10.10.20.30\n  - address: ' 10.10.20.30 '"},
		{name: "nil endpoint", entries: "- hosts: [api.example.com]\n  endpoints:\n  - null"},
		{name: "duplicate host across entries", entries: "- hosts: [API.example.com.]\n  endpoints:\n  - address: 10.10.20.30\n- hosts: [api.example.com]\n  endpoints:\n  - address: 10.10.20.31"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := "egressGateways:\n- name: egress\n  namespace: agentio-system\n  serviceEntries:\n" + test.entries + "\n"
			if _, err := applyAgentioConfig(content, nil); err == nil {
				t.Fatal("applyAgentioConfig() accepted an invalid static service entry")
			}
		})
	}
}

func TestPolicyCollectionsTrackTypedResources(t *testing.T) {
	ctx := t.Context()
	traffic := &agentsv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: "demo", Name: "traffic",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-a"},
	}}
	globalTraffic := &agentsv1alpha1.GlobalTrafficPolicy{ObjectMeta: metav1.ObjectMeta{
		Name: "global-traffic", Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-b"},
	}}
	security := &agentsv1alpha1.SecurityProfile{ObjectMeta: metav1.ObjectMeta{
		Namespace: "demo", Name: "security",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-c"},
	}}
	globalSecurity := &agentsv1alpha1.GlobalSecurityProfile{ObjectMeta: metav1.ObjectMeta{
		Name: "global-security", Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-d"},
	}}
	r := newTestRegistry(t, ctx, nil, []runtime.Object{traffic, globalTraffic, security, globalSecurity})

	if got := r.TrafficPolicies.List(); len(got) != 2 {
		t.Fatalf("traffic policy collection size = %d, want 2", len(got))
	}
	if got := r.SecurityProfiles.List(); len(got) != 2 {
		t.Fatalf("security profile collection size = %d, want 2", len(got))
	}
	if got := r.TrafficPolicies.GetKey("namespaced/demo/traffic"); got == nil || got.Namespace != "demo" ||
		got.SandboxUID != "sandbox-a" || got.Global {
		t.Fatalf("namespaced traffic policy = %+v", got)
	}
	if got := r.TrafficPolicies.GetKey("global/global-traffic"); got == nil || got.SandboxUID != "sandbox-b" || !got.Global {
		t.Fatalf("global traffic policy = %+v", got)
	}
	if got := r.SecurityProfiles.GetKey("namespaced/demo/security"); got == nil || got.SandboxUID != "sandbox-c" || got.Global {
		t.Fatalf("namespaced security profile = %+v", got)
	}
	if got := r.SecurityProfiles.GetKey("global/global-security"); got == nil || got.SandboxUID != "sandbox-d" || !got.Global {
		t.Fatalf("global security profile = %+v", got)
	}
}

func TestAgentioConfigRetainsLastKnownGoodOverlay(t *testing.T) {
	ctx := t.Context()
	base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"}, Data: map[string]string{
		"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n  port: 9002\n",
	}}
	primary := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"}, Data: map[string]string{
		"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
	}}
	r := newTestRegistry(t, ctx, []runtime.Object{base, primary}, nil)

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value.GetSandboxExtProc().GetService() != "base.agentio-system.svc.cluster.local" ||
		len(config.Value.GetEgressGateways()) != 1 {
		t.Fatalf("effective config = %+v", config)
	}

	primary.Data["config"] = "egressGateways: ["
	if _, err := r.client.CoreV1().ConfigMaps(primary.Namespace).Update(ctx, primary, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update malformed primary ConfigMap: %v", err)
	}
	if err := wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, time.Second, true, func(context.Context) (bool, error) {
		current := r.AgentioConfig.GetKey("effective")
		return current != nil && current.Value.GetSandboxExtProc().GetService() == "base.agentio-system.svc.cluster.local" &&
			len(current.Value.GetEgressGateways()) == 1, nil
	}); err != nil {
		t.Fatalf("last known good config was not retained: %v", err)
	}
}

type testRegistry struct {
	*Registry
	client kubeclient.Interface
}

func newTestRegistry(t *testing.T, ctx context.Context, kubeObjects, policyObjects []runtime.Object) *testRegistry {
	return newTestRegistryWithAgentioConfigMaps(t, ctx, kubeObjects, policyObjects, nil)
}

func newTestRegistryWithAgentioConfigMaps(
	t *testing.T,
	ctx context.Context,
	kubeObjects, policyObjects []runtime.Object,
	agentioConfigMaps *AgentioConfigMapOptions,
) *testRegistry {
	t.Helper()
	objects := append(append([]runtime.Object(nil), kubeObjects...), policyObjects...)
	client := &fakeKubeClient{
		Client: kube.NewFakeClient(objects...),
		watcher: newFakeGatewayCRDWatcher(
			trafficPolicyResource,
			globalTrafficPolicyResource,
			securityProfileResource,
			globalSecurityProfileResource,
		),
	}
	r, err := New(client, Options{
		ClusterID: "test", TrustDomain: "cluster.local", RootNamespace: "agentio-system",
		DebounceAfter: time.Millisecond, DebounceMax: 5 * time.Millisecond,
		AgentioConfigMaps: agentioConfigMaps,
	}, ctx.Done())
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	client.Run(ctx.Done())
	if err := wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, time.Second, true, func(context.Context) (bool, error) {
		return r.HasSynced(), nil
	}); err != nil {
		t.Fatalf("registry did not sync: %v", err)
	}
	return &testRegistry{
		Registry: r,
		client:   client.Kube(),
	}
}
