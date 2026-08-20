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

package model

import (
	"reflect"
	"testing"

	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/util/sets"
)

type fakeAgentioResourceDiscovery struct {
	gotProxy     *Proxy
	gotTypeURL   string
	gotRequested sets.Set[ConfigKey]
	resources    []AgentioResource
}

func (f *fakeAgentioResourceDiscovery) AgentioResourcesForProxy(
	proxy *Proxy,
	typeURL string,
	requested sets.Set[ConfigKey],
) []AgentioResource {
	f.gotProxy, f.gotTypeURL, f.gotRequested = proxy, typeURL, requested
	return f.resources
}

var _ AgentioResourceDiscovery = &fakeAgentioResourceDiscovery{}

func TestAgentioResourceDiscoveryContract(t *testing.T) {
	proxy := &Proxy{}
	requested := sets.New[ConfigKey](ConfigKey{Name: "requested"})
	resource := &extensions.SniTrafficPolicy{}
	fake := &fakeAgentioResourceDiscovery{
		resources: []AgentioResource{{Name: "ns/policy", Resource: resource}},
	}
	var discovery AgentioResourceDiscovery = fake

	got := discovery.AgentioResourcesForProxy(proxy, "type.googleapis.com/agentio.SniTrafficPolicy", requested)
	if fake.gotProxy != proxy {
		t.Errorf("got proxy %p, want %p", fake.gotProxy, proxy)
	}
	if fake.gotTypeURL != "type.googleapis.com/agentio.SniTrafficPolicy" {
		t.Errorf("got type URL %q, want %q", fake.gotTypeURL, "type.googleapis.com/agentio.SniTrafficPolicy")
	}
	if !reflect.DeepEqual(fake.gotRequested, requested) {
		t.Errorf("got requested set %+v, want %+v", fake.gotRequested, requested)
	}
	if len(got) != 1 || got[0].Name != "ns/policy" || got[0].Resource != resource {
		t.Errorf("got resources %+v, want envelope name ns/policy and resource pointer %p", got, resource)
	}
}

func TestPolicyBindingResourceName(t *testing.T) {
	cases := []struct {
		testName  string
		namespace string
		name      string
		want      string
	}{
		{testName: "pod NamespacedName", namespace: "ns", name: "pod-1", want: "workload://ns/pod-1"},
		{testName: "default namespace", namespace: "default", name: "test", want: "workload://default/test"},
		{testName: "empty reference", want: "workload:///"},
	}
	for _, tc := range cases {
		t.Run(tc.testName, func(t *testing.T) {
			if got := PolicyBindingResourceName(tc.namespace, tc.name); got != tc.want {
				t.Errorf("PolicyBindingResourceName(%q, %q) = %q, want %q", tc.namespace, tc.name, got, tc.want)
			}
		})
	}
}

func TestPolicyBindingResourceNameMatchesHelper(t *testing.T) {
	p := PolicyBinding{Name: PolicyBindingResourceName("ns", "pod-1")}
	if got, want := p.ResourceName(), PolicyBindingResourceName("ns", "pod-1"); got != want {
		t.Errorf("PolicyBinding.ResourceName() = %q, want %q", got, want)
	}
	if got, want := p.ResourceName(), "workload://ns/pod-1"; got != want {
		t.Errorf("PolicyBinding.ResourceName() = %q, want %q", got, want)
	}
}

func policyBindingFor(namespace, name string, refs map[string]*extensions.PolicyReference) *extensions.PolicyBinding {
	return &extensions.PolicyBinding{
		TargetRef: &extensions.PolicyBinding_Workload{
			Workload: &extensions.WorkloadReference{Namespace: namespace, Name: name},
		},
		PolicyRefs: refs,
	}
}

func TestPolicyBindingEquals(t *testing.T) {
	base := PolicyBinding{
		Name: "workload://ns/pod-1",
		Binding: policyBindingFor("ns", "pod-1", map[string]*extensions.PolicyReference{
			"type.googleapis.com/A": {ResourceNames: []string{"ns/a"}},
		}),
	}
	cases := []struct {
		name  string
		a     PolicyBinding
		b     PolicyBinding
		equal bool
	}{
		{name: "identical", a: base, b: base, equal: true},
		{
			name: "same content different pointers",
			a:    base,
			b: PolicyBinding{
				Name: "workload://ns/pod-1",
				Binding: policyBindingFor("ns", "pod-1", map[string]*extensions.PolicyReference{
					"type.googleapis.com/A": {ResourceNames: []string{"ns/a"}},
				}),
			},
			equal: true,
		},
		{
			name:  "different resource name",
			a:     base,
			b:     PolicyBinding{Name: "workload://ns/pod-2", Binding: base.Binding},
			equal: false,
		},
		{
			name: "different proto resource names",
			a:    base,
			b: PolicyBinding{
				Name: "workload://ns/pod-1",
				Binding: policyBindingFor("ns", "pod-1", map[string]*extensions.PolicyReference{
					"type.googleapis.com/A": {ResourceNames: []string{"ns/b"}},
				}),
			},
			equal: false,
		},
		{
			name: "different proto type url",
			a:    base,
			b: PolicyBinding{
				Name: "workload://ns/pod-1",
				Binding: policyBindingFor("ns", "pod-1", map[string]*extensions.PolicyReference{
					"type.googleapis.com/B": {ResourceNames: []string{"ns/a"}},
				}),
			},
			equal: false,
		},
		{
			name:  "nil vs non-nil proto",
			a:     base,
			b:     PolicyBinding{Name: "workload://ns/pod-1"},
			equal: false,
		},
		{
			name:  "both nil protos",
			a:     PolicyBinding{Name: "workload://ns/pod-1"},
			b:     PolicyBinding{Name: "workload://ns/pod-1"},
			equal: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Equals(tc.b); got != tc.equal {
				t.Errorf("Equals() = %v, want %v", got, tc.equal)
			}
			if got := tc.b.Equals(tc.a); got != tc.equal {
				t.Errorf("Equals() reversed = %v, want %v", got, tc.equal)
			}
		})
	}
}

func TestPolicyBindingConfigKey(t *testing.T) {
	p := PolicyBinding{Name: "workload://ns/pod-1", Binding: policyBindingFor("ns", "pod-1", nil)}
	want := ConfigKey{Kind: kind.PolicyBinding, Name: "workload://ns/pod-1"}
	if got := p.ConfigKey(); !reflect.DeepEqual(got, want) {
		t.Errorf("ConfigKey() = %+v, want %+v", got, want)
	}
}
