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

package xds

import (
	"testing"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/serviceregistry/memory"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"
)

const testGatewayNS = "agentio-system"

type sniPolicyStubDiscovery struct {
	*memory.ServiceDiscovery

	policies []model.AgentioResource

	resourceOverrides map[string][]model.AgentioResource
	calls             map[string]int
	requests          map[string]sets.Set[model.ConfigKey]
}

func newSniPolicyStubDiscovery(policies []model.AgentioResource) *sniPolicyStubDiscovery {
	return &sniPolicyStubDiscovery{
		ServiceDiscovery:  memory.NewServiceDiscovery(),
		policies:          policies,
		resourceOverrides: map[string][]model.AgentioResource{},
		calls:             map[string]int{},
		requests:          map[string]sets.Set[model.ConfigKey]{},
	}
}

func (s *sniPolicyStubDiscovery) AgentioResourcesForProxy(
	_ *model.Proxy,
	typeURL string,
	requested sets.Set[model.ConfigKey],
) []model.AgentioResource {
	s.calls[typeURL]++
	s.requests[typeURL] = requested
	if resources, ok := s.resourceOverrides[typeURL]; ok {
		return resources
	}
	if typeURL == v3.SniTrafficPolicyType {
		return s.policies
	}
	return nil
}

var (
	_ model.ServiceDiscovery         = &sniPolicyStubDiscovery{}
	_ model.AgentioResourceDiscovery = &sniPolicyStubDiscovery{}
)

func newSniPolicyServer(t test.Failer, stub *sniPolicyStubDiscovery) *DiscoveryServer {
	t.Helper()
	env := model.NewEnvironment()
	env.ServiceDiscovery = stub
	return &DiscoveryServer{Env: env}
}

func agentioResourceGeneratorForType(
	t test.Failer,
	server *DiscoveryServer,
	typeURL string,
) AgentioResourceGenerator {
	t.Helper()
	for _, descriptor := range AgentioResourceDescriptors() {
		if descriptor.TypeURL == typeURL {
			return AgentioResourceGenerator{Server: server, Descriptor: descriptor}
		}
	}
	t.Fatalf("descriptor for %s not found", typeURL)
	return AgentioResourceGenerator{}
}

func newSniPolicyPush(request bool, updated sets.Set[model.ConfigKey]) *model.PushRequest {
	req := &model.PushRequest{Push: model.NewPushContext(), ConfigsUpdated: updated}
	if request {
		req.Forced = true
		req.Reason = model.NewReasonStats(model.ProxyRequest)
	}
	return req
}

func testPolicy(namespace, name string) model.AgentioResource {
	return model.AgentioResource{
		Name: namespace + "/" + name,
		Resource: &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{{
			Action: extensions.SniAction_SNI_ACTION_TLS_TERMINATION,
			Match:  &extensions.SniMatch{Sni: []string{"api.example.com"}},
		}}},
	}
}

func names(resources model.Resources) []string {
	out := make([]string, 0, len(resources))
	for _, resource := range resources {
		out = append(out, resource.Name)
	}
	return out
}

func TestSniPolicyResources(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	stub := newSniPolicyStubDiscovery([]model.AgentioResource{testPolicy(testGatewayNS, "allow-all")})
	gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)

	resources, removed, _, usedDelta, err := gen.GenerateDeltas(
		&model.Proxy{ID: "proxy"}, newSniPolicyPush(true, nil),
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType})

	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	assert.Equal(t, names(resources), []string{testGatewayNS + "/allow-all"})
	assert.Equal(t, len(removed), 0)
	assert.Equal(t, resources[0].Resource.TypeUrl, v3.SniTrafficPolicyType)
}

func TestSniPolicyForcedStaleResourceCleanup(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	stub := newSniPolicyStubDiscovery([]model.AgentioResource{testPolicy("ns-live", "allow")})
	gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)

	resources, removed, _, usedDelta, err := gen.GenerateDeltas(
		&model.Proxy{ID: "proxy"}, newSniPolicyPush(true, nil),
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType, ResourceNames: sets.New(
			"ns-z/removed", "ns-live/allow", "ns-a/removed")})

	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	assert.Equal(t, names(resources), []string{"ns-live/allow"})
	assert.Equal(t, removed, []string{"ns-a/removed", "ns-z/removed"})
}

func TestSniPolicySkipsUnrelatedForcedPush(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	stub := newSniPolicyStubDiscovery([]model.AgentioResource{testPolicy("ns-live", "allow")})
	gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)

	resources, removed, _, usedDelta, err := gen.GenerateDeltas(
		&model.Proxy{ID: "proxy"},
		&model.PushRequest{Push: model.NewPushContext(), Forced: true},
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType, ResourceNames: sets.New("ns-live/allow")})

	assert.NoError(t, err)
	assert.Equal(t, usedDelta, false)
	assert.Equal(t, resources, nil)
	assert.Equal(t, removed, nil)
	assert.Equal(t, stub.calls[v3.SniTrafficPolicyType], 0)
}

func TestSniPolicyDropsInvalidResources(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	valid := testPolicy("ns-a", "valid")
	var typedNil *extensions.SniTrafficPolicy
	cases := []model.AgentioResource{
		{Resource: testPolicy("ns-a", "missing-name").Resource},
		{Name: "ns-a/untyped-nil"},
		{Name: "ns-a/typed-nil", Resource: typedNil},
		{Name: "ns-a/wrong-type", Resource: &extensions.PolicyReference{}},
	}
	for i, invalid := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			stub := newSniPolicyStubDiscovery(nil)
			stub.resourceOverrides[v3.SniTrafficPolicyType] = []model.AgentioResource{invalid, valid}
			gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)
			resources, removed, _, usedDelta, err := gen.GenerateDeltas(
				&model.Proxy{ID: "proxy"}, newSniPolicyPush(true, nil),
				&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType})
			assert.NoError(t, err)
			assert.Equal(t, usedDelta, true)
			assert.Equal(t, names(resources), []string{"ns-a/valid"})
			assert.Equal(t, len(removed), 0)
		})
	}
}

func TestSniTrafficPolicyIncrementalRemoval(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)
	stub := newSniPolicyStubDiscovery([]model.AgentioResource{testPolicy("ns-a", "live")})
	gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)
	updated := sets.New(
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns-a/live"},
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns-b/gone"},
	)

	resources, removed, _, usedDelta, err := gen.GenerateDeltas(
		&model.Proxy{ID: "proxy"}, newSniPolicyPush(false, updated),
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType})

	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	assert.Equal(t, names(resources), []string{"ns-a/live"})
	assert.Equal(t, removed, []string{"ns-b/gone"})
	assert.Equal(t, stub.requests[v3.SniTrafficPolicyType], updated)
}

func TestSniPolicyFeatureFlagOff(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, false)
	stub := newSniPolicyStubDiscovery([]model.AgentioResource{testPolicy("ns-a", "live")})
	gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.SniTrafficPolicyType)

	resources, removed, _, usedDelta, err := gen.GenerateDeltas(
		&model.Proxy{ID: "proxy"}, newSniPolicyPush(true, nil),
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType})

	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	if resources == nil || removed == nil {
		t.Fatalf("flag-off delta must return empty non-nil slices, got resources=%#v removed=%#v", resources, removed)
	}
	assert.Equal(t, stub.calls[v3.SniTrafficPolicyType], 0)
}

func TestAgentioResourceDescriptors(t *testing.T) {
	descriptors := AgentioResourceDescriptors()
	assert.Equal(t, len(descriptors), 1)
	counts := map[string]int{}
	for _, descriptor := range descriptors {
		counts[descriptor.TypeURL]++
	}
	assert.Equal(t, counts[v3.SniTrafficPolicyType], 1)
}

func TestSniPolicyPushedBeforeWorkloadReferences(t *testing.T) {
	policyIndex, workloadIndex := -1, -1
	for i, typeURL := range PushOrder {
		switch typeURL {
		case v3.SniTrafficPolicyType:
			policyIndex = i
		case v3.WorkloadType:
			workloadIndex = i
		}
	}
	if policyIndex < 0 || workloadIndex < 0 || policyIndex > workloadIndex {
		t.Fatalf("push order must place policy before Workload: policy=%d workload=%d", policyIndex, workloadIndex)
	}
}
