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
