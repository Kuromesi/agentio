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
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"
)

// The fake discovery server in pilot/test/xds cannot exercise these generators
// end-to-end because its memory registry does not implement
// model.AgentioResourceDiscovery. These tests therefore drive the generator
// directly against a hand-built DiscoveryServer/Environment with a stub
// ServiceDiscovery.

const testGatewayNS = "agentio-system"

// sniPolicyStubDiscovery embeds the memory registry (which satisfies the whole
// model.ServiceDiscovery surface) and implements the optional Agentio resource
// discovery capability used by the resource generator.
type sniPolicyStubDiscovery struct {
	*memory.ServiceDiscovery

	bindings []model.PolicyBinding
	configs  []model.WorkloadConfig
	policies []model.AgentioResource
	// resourceOverrides lets malformed generic envelopes be exercised without
	// weakening the normal typed fixtures used by the rest of the tests.
	resourceOverrides map[string][]model.AgentioResource

	// Recorded arguments, so tests can assert the generator forwards the requested
	// ConfigKey set rather than silently dropping it.
	calls    map[string]int
	requests map[string]sets.Set[model.ConfigKey]
}

func newSniPolicyStubDiscovery(bindings []model.PolicyBinding, policies []model.AgentioResource) *sniPolicyStubDiscovery {
	return &sniPolicyStubDiscovery{
		ServiceDiscovery:  memory.NewServiceDiscovery(),
		bindings:          bindings,
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
	switch typeURL {
	case v3.WorkloadConfigType:
		return slices.Map(s.configs, func(v model.WorkloadConfig) model.AgentioResource {
			return model.AgentioResource{Name: v.ResourceName(), Resource: v.Config}
		})
	case v3.PolicyBindingType:
		return slices.Map(s.bindings, func(v model.PolicyBinding) model.AgentioResource {
			return model.AgentioResource{Name: v.ResourceName(), Resource: v.Binding}
		})
	case v3.SniTrafficPolicyType:
		return s.policies
	default:
		return nil
	}
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

func newSniPolicyPush(forced bool, updated sets.Set[model.ConfigKey]) *model.PushRequest {
	return &model.PushRequest{
		Push:           model.NewPushContext(),
		Forced:         forced,
		ConfigsUpdated: updated,
	}
}

func testAgentioProxy() *model.Proxy {
	return &model.Proxy{ID: "test-agentio-proxy"}
}

func testBinding(namespace, name string) model.PolicyBinding {
	return model.PolicyBinding{
		Name: model.PolicyBindingResourceName(namespace, name),
		Binding: &extensions.PolicyBinding{
			TargetRef: &extensions.PolicyBinding_Workload{
				Workload: &extensions.WorkloadReference{Namespace: namespace, Name: name},
			},
			PolicyRefs: map[string]*extensions.PolicyReference{
				v3.SniTrafficPolicyType: {ResourceNames: []string{testGatewayNS + "/allow-all"}},
			},
		},
	}
}

func testPolicy(ns, name string) model.AgentioResource {
	return model.AgentioResource{
		Name: ns + "/" + name,
		Resource: &extensions.SniTrafficPolicy{
			Rules: []*extensions.SniRule{
				{
					Action: extensions.SniAction_SNI_ACTION_TLS_TERMINATION,
					Match:  &extensions.SniMatch{Sni: []string{"api.example.com"}},
				},
			},
		},
	}
}

func testWorkloadConfig(ns, name string) model.WorkloadConfig {
	return model.WorkloadConfig{
		Name:      name,
		Namespace: ns,
		Config:    &extensions.WorkloadConfig{},
	}
}

func names(resources model.Resources) []string {
	out := make([]string, 0, len(resources))
	for _, r := range resources {
		out = append(out, r.Name)
	}
	return out
}

func TestSniPolicyResources(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	stub := newSniPolicyStubDiscovery(
		[]model.PolicyBinding{testBinding("ns", "uid-1"), testBinding("ns", "uid-2")},
		[]model.AgentioResource{testPolicy(testGatewayNS, "allow-all")},
	)
	s := newSniPolicyServer(t, stub)
	proxy := testAgentioProxy()

	t.Run("bindings", func(t *testing.T) {
		gen := agentioResourceGeneratorForType(t, s, v3.PolicyBindingType)
		w := &model.WatchedResource{TypeUrl: v3.PolicyBindingType}
		res, removed, _, usedDelta, err := gen.GenerateDeltas(proxy, newSniPolicyPush(true, nil), w)
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, true)
		assert.Equal(t, sets.SortedList(sets.New(names(res)...)), []string{"workload://ns/uid-1", "workload://ns/uid-2"})
		assert.Equal(t, len(removed), 0)
		// The payload must be the binding proto, not the wrapper.
		assert.Equal(t, res[0].Resource.TypeUrl,
			"type.googleapis.com/kruise.networking.extensions.v1.PolicyBinding")
	})

	t.Run("policies", func(t *testing.T) {
		gen := agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType)
		w := &model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType}
		res, removed, _, usedDelta, err := gen.GenerateDeltas(proxy, newSniPolicyPush(true, nil), w)
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, true)
		assert.Equal(t, names(res), []string{testGatewayNS + "/allow-all"})
		assert.Equal(t, len(removed), 0)
		assert.Equal(t, res[0].Resource.TypeUrl,
			"type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy")
	})
}

func TestSniPolicyForcedStaleResourceCleanup(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	cases := []struct {
		name          string
		typeURL       string
		bindings      []model.PolicyBinding
		policies      []model.AgentioResource
		watched       sets.Set[string]
		wantResources []string
		wantRemoved   []string
	}{
		{
			name:          "PolicyBinding workload reference names",
			typeURL:       v3.PolicyBindingType,
			bindings:      []model.PolicyBinding{testBinding("ns-live", "uid-live")},
			watched:       sets.New("workload://ns-live/uid-z-stale", "workload://ns-live/uid-live", "workload://ns-live/uid-a-stale"),
			wantResources: []string{"workload://ns-live/uid-live"},
			wantRemoved:   []string{"workload://ns-live/uid-a-stale", "workload://ns-live/uid-z-stale"},
		},
		{
			name:          "SniTrafficPolicy resource name",
			typeURL:       v3.SniTrafficPolicyType,
			policies:      []model.AgentioResource{testPolicy("ns-live", "allow")},
			watched:       sets.New("ns-z/removed", "ns-live/allow", "ns-a/removed"),
			wantResources: []string{"ns-live/allow"},
			wantRemoved:   []string{"ns-a/removed", "ns-z/removed"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newSniPolicyStubDiscovery(tc.bindings, tc.policies)
			s := newSniPolicyServer(t, stub)
			gen := agentioResourceGeneratorForType(t, s, tc.typeURL)

			resources, removed, _, usedDelta, err := gen.GenerateDeltas(
				testAgentioProxy(),
				newSniPolicyPush(true, nil),
				&model.WatchedResource{TypeUrl: tc.typeURL, ResourceNames: tc.watched},
			)
			assert.NoError(t, err)
			assert.Equal(t, usedDelta, true)
			assert.Equal(t, names(resources), tc.wantResources)
			assert.Equal(t, removed, tc.wantRemoved)
		})
	}
}

func TestSniPolicySotWAdapter(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	stub := newSniPolicyStubDiscovery(
		[]model.PolicyBinding{testBinding("ns", "uid-1")},
		nil,
	)
	s := newSniPolicyServer(t, stub)
	gen := agentioResourceGeneratorForType(t, s, v3.PolicyBindingType)

	res, details, err := gen.Generate(
		testAgentioProxy(),
		&model.WatchedResource{TypeUrl: v3.PolicyBindingType},
		newSniPolicyPush(true, nil),
	)
	assert.NoError(t, err)
	assert.Equal(t, names(res), []string{"workload://ns/uid-1"})
	assert.Equal(t, details, model.XdsLogDetails{})
}

func TestSniPolicyDropsInvalidResources(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	valid := model.AgentioResource{
		Name:     "ns-a/valid",
		Resource: testPolicy("ns-a", "valid").Resource,
	}
	var typedNil *extensions.SniTrafficPolicy
	cases := []struct {
		name    string
		invalid model.AgentioResource
	}{
		{
			name: "empty name",
			invalid: model.AgentioResource{
				Resource: testPolicy("ns-a", "missing-name").Resource,
			},
		},
		{
			name:    "untyped nil protobuf",
			invalid: model.AgentioResource{Name: "ns-a/untyped-nil"},
		},
		{
			name: "typed nil protobuf",
			invalid: model.AgentioResource{
				Name: "ns-a/typed-nil", Resource: typedNil,
			},
		},
		{
			name: "wrong protobuf type",
			invalid: model.AgentioResource{
				Name: "ns-a/wrong-type", Resource: &extensions.PolicyBinding{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newSniPolicyStubDiscovery(nil, nil)
			stub.resourceOverrides[v3.SniTrafficPolicyType] = []model.AgentioResource{tc.invalid, valid}
			s := newSniPolicyServer(t, stub)
			gen := agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType)

			res, removed, _, usedDelta, err := gen.GenerateDeltas(
				testAgentioProxy(),
				newSniPolicyPush(true, nil),
				&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType},
			)
			assert.NoError(t, err)
			assert.Equal(t, usedDelta, true)
			assert.Equal(t, names(res), []string{"ns-a/valid"})
			assert.Equal(t, res[0].Resource.TypeUrl, v3.SniTrafficPolicyType)
			assert.Equal(t, len(removed), 0)
		})
	}
}

// TestPolicyBindingRemovalName pins the complete resource name carried in the
// synthetic ConfigKey.
func TestPolicyBindingRemovalName(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	// "ns/gone" was updated but no longer exists; "ns/live" still does.
	stub := newSniPolicyStubDiscovery([]model.PolicyBinding{testBinding("ns", "live")}, nil)
	s := newSniPolicyServer(t, stub)
	gen := agentioResourceGeneratorForType(t, s, v3.PolicyBindingType)

	updated := sets.New(
		model.PolicyBinding{Name: "workload://ns/gone"}.ConfigKey(),
		model.PolicyBinding{Name: "workload://ns/live"}.ConfigKey(),
	)
	// These are xDS resources, so the synthetic key has no Kubernetes namespace.
	for k := range updated {
		assert.Equal(t, k.Namespace, "")
		assert.Equal(t, k.Kind, kind.PolicyBinding)
	}

	w := &model.WatchedResource{TypeUrl: v3.PolicyBindingType}
	res, removed, _, usedDelta, err := gen.GenerateDeltas(testAgentioProxy(), newSniPolicyPush(false, updated), w)
	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	assert.Equal(t, names(res), []string{"workload://ns/live"})
	assert.Equal(t, removed, []string{"workload://ns/gone"})

	// The requested ConfigKey set must be forwarded to the index, not dropped.
	assert.Equal(t, stub.requests[v3.PolicyBindingType], updated)
}

// TestSniTrafficPolicyRemovalName is the counterpart for SNI policy resources.
func TestSniTrafficPolicyRemovalName(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	stub := newSniPolicyStubDiscovery(nil, []model.AgentioResource{testPolicy("ns-a", "live")})
	s := newSniPolicyServer(t, stub)
	gen := agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType)

	updated := sets.New(
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns-a/live"},
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns-b/gone"},
	)
	w := &model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType}
	res, removed, _, usedDelta, err := gen.GenerateDeltas(testAgentioProxy(), newSniPolicyPush(false, updated), w)
	assert.NoError(t, err)
	assert.Equal(t, usedDelta, true)
	assert.Equal(t, names(res), []string{"ns-a/live"})
	assert.Equal(t, removed, []string{"ns-b/gone"})
}

// TestSniPolicyIrrelevantIncrementalPush: an incremental push carrying only
// unrelated kinds must be a no-op, and must not reach the ambient index.
func TestSniPolicyIrrelevantIncrementalPush(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, true)

	stub := newSniPolicyStubDiscovery(
		[]model.PolicyBinding{testBinding("ns", "uid-1")},
		[]model.AgentioResource{testPolicy("ns-a", "live")},
	)
	s := newSniPolicyServer(t, stub)

	// A Service update, plus each generator's *sibling* kind, so we also prove the
	// two generators do not answer for each other's kind.
	updated := sets.New(
		model.ConfigKey{Kind: kind.Service, Name: "svc", Namespace: "ns-a"},
	)
	proxy := testAgentioProxy()
	held := sets.New("workload://ns/uid-1", "ns-a/live")

	for _, sub := range []struct {
		typeURL string
		gen     model.XdsDeltaResourceGenerator
	}{
		{v3.PolicyBindingType, agentioResourceGeneratorForType(t, s, v3.PolicyBindingType)},
		{v3.SniTrafficPolicyType, agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType)},
	} {
		w := &model.WatchedResource{TypeUrl: sub.typeURL, ResourceNames: held}
		res, removed, _, usedDelta, err := sub.gen.GenerateDeltas(proxy, newSniPolicyPush(false, updated), w)
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, false)
		assert.Equal(t, len(res), 0)
		assert.Equal(t, len(removed), 0)
	}

	// Cross-kind isolation: a PolicyBinding update must not make the SNI policy
	// generator respond, and vice versa.
	bindingOnly := sets.New(model.PolicyBinding{Name: "workload://ns/uid-1"}.ConfigKey())
	_, _, _, usedDelta, err := agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType).GenerateDeltas(
		proxy, newSniPolicyPush(false, bindingOnly),
		&model.WatchedResource{TypeUrl: v3.SniTrafficPolicyType, ResourceNames: held})
	assert.NoError(t, err)
	assert.Equal(t, usedDelta, false)

	policyOnly := sets.New(model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns-a/live"})
	_, _, _, usedDelta, err = agentioResourceGeneratorForType(t, s, v3.PolicyBindingType).GenerateDeltas(
		proxy, newSniPolicyPush(false, policyOnly),
		&model.WatchedResource{TypeUrl: v3.PolicyBindingType, ResourceNames: held})
	assert.NoError(t, err)
	assert.Equal(t, usedDelta, false)

	assert.Equal(t, stub.calls[v3.PolicyBindingType], 0)
	assert.Equal(t, stub.calls[v3.SniTrafficPolicyType], 0)
}

// TestSniPolicyFeatureFlagOff verifies that disabled resource types return
// nothing, report no removals, and do not consult the Agentio resource source.
func TestSniPolicyFeatureFlagOff(t *testing.T) {
	test.SetForTest(t, &features.EnableSniTrafficPolicy, false)

	stub := newSniPolicyStubDiscovery(
		[]model.PolicyBinding{testBinding("ns", "uid-1")},
		[]model.AgentioResource{testPolicy("ns-a", "live")},
	)
	s := newSniPolicyServer(t, stub)
	held := sets.New("workload://ns/uid-1", "ns-a/live")

	for _, sub := range []struct {
		typeURL string
		gen     model.XdsDeltaResourceGenerator
	}{
		{v3.PolicyBindingType, agentioResourceGeneratorForType(t, s, v3.PolicyBindingType)},
		{v3.SniTrafficPolicyType, agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType)},
	} {
		w := &model.WatchedResource{TypeUrl: sub.typeURL, ResourceNames: held}
		// A forced push is still suppressed by the feature flag.
		res, removed, _, usedDelta, err := sub.gen.GenerateDeltas(testAgentioProxy(), newSniPolicyPush(true, nil), w)
		assert.NoError(t, err)
		assert.Equal(t, len(res), 0)
		assert.Equal(t, len(removed), 0)
		assert.Equal(t, usedDelta, false)
	}
	assert.Equal(t, stub.calls[v3.PolicyBindingType], 0)
	assert.Equal(t, stub.calls[v3.SniTrafficPolicyType], 0)

	// A minimal proxy with the flag off must also not panic.
	for _, sub := range []model.XdsDeltaResourceGenerator{
		agentioResourceGeneratorForType(t, s, v3.PolicyBindingType),
		agentioResourceGeneratorForType(t, s, v3.SniTrafficPolicyType),
	} {
		_, _, _, _, err := sub.GenerateDeltas(&model.Proxy{ID: "anon"}, newSniPolicyPush(true, nil),
			&model.WatchedResource{TypeUrl: v3.PolicyBindingType})
		assert.NoError(t, err)
	}
}

func TestAgentioResourceGeneratorWorkloadConfigDelta(t *testing.T) {
	live := testWorkloadConfig("sandbox-ns", "default")

	t.Run("plain memory discovery removes stale watched resources", func(t *testing.T) {
		source := memory.NewServiceDiscovery()
		_, implementsResourceDiscovery := any(source).(model.AgentioResourceDiscovery)
		assert.Equal(t, implementsResourceDiscovery, false)

		env := model.NewEnvironment()
		env.ServiceDiscovery = source
		gen := agentioResourceGeneratorForType(t, &DiscoveryServer{Env: env}, v3.WorkloadConfigType)

		resources, removed, _, usedDelta, err := gen.GenerateDeltas(nil, &model.PushRequest{Forced: true},
			&model.WatchedResource{TypeUrl: v3.WorkloadConfigType, ResourceNames: sets.New(
				"sandbox-ns/z-held", "sandbox-ns/a-held",
			)})
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, true)
		assert.Equal(t, len(resources), 0)
		assert.Equal(t, removed, []string{"sandbox-ns/a-held", "sandbox-ns/z-held"})
	})

	t.Run("forced request emits live resource and sorted stale removals", func(t *testing.T) {
		stub := newSniPolicyStubDiscovery(nil, nil)
		stub.configs = []model.WorkloadConfig{live}
		gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.WorkloadConfigType)

		resources, removed, _, usedDelta, err := gen.GenerateDeltas(nil, &model.PushRequest{Forced: true},
			&model.WatchedResource{TypeUrl: v3.WorkloadConfigType, ResourceNames: sets.New(
				"sandbox-ns/z-stale", live.ResourceName(), "sandbox-ns/a-stale",
			)})
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, true)
		assert.Equal(t, names(resources), []string{"sandbox-ns/default"})
		assert.Equal(t, resources[0].Resource.TypeUrl, v3.WorkloadConfigType)
		assert.Equal(t, removed, []string{"sandbox-ns/a-stale", "sandbox-ns/z-stale"})
	})

	t.Run("incremental update forwards exact config key", func(t *testing.T) {
		stub := newSniPolicyStubDiscovery(nil, nil)
		stub.configs = []model.WorkloadConfig{live}
		gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.WorkloadConfigType)
		updated := sets.New(live.ConfigKey())

		resources, removed, _, usedDelta, err := gen.GenerateDeltas(nil, &model.PushRequest{ConfigsUpdated: updated},
			&model.WatchedResource{TypeUrl: v3.WorkloadConfigType})
		assert.NoError(t, err)
		assert.Equal(t, usedDelta, true)
		assert.Equal(t, names(resources), []string{"sandbox-ns/default"})
		assert.Equal(t, len(removed), 0)
		assert.Equal(t, stub.requests[v3.WorkloadConfigType], updated)
	})

	t.Run("unrelated config kind does not call discovery", func(t *testing.T) {
		stub := newSniPolicyStubDiscovery(nil, nil)
		gen := agentioResourceGeneratorForType(t, newSniPolicyServer(t, stub), v3.WorkloadConfigType)
		updated := sets.New(model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "sandbox-ns/unrelated"})

		resources, removed, _, usedDelta, err := gen.GenerateDeltas(nil, &model.PushRequest{ConfigsUpdated: updated},
			&model.WatchedResource{TypeUrl: v3.WorkloadConfigType})
		assert.NoError(t, err)
		assert.Equal(t, len(resources), 0)
		assert.Equal(t, len(removed), 0)
		assert.Equal(t, usedDelta, false)
		assert.Equal(t, stub.calls[v3.WorkloadConfigType], 0)
	})
}

func TestSniPolicyDescriptors(t *testing.T) {
	descriptors := AgentioResourceDescriptors()
	assert.Equal(t, len(descriptors), 3)

	counts := map[string]int{}
	for _, descriptor := range descriptors {
		counts[descriptor.TypeURL]++
		switch descriptor.TypeURL {
		case v3.WorkloadConfigType:
			assert.Equal(t, descriptor.ConfigKind, kind.WorkloadConfig)
			assert.Equal(t, descriptor.ResourceNameFromKey(model.ConfigKey{
				Namespace: "sandbox-ns", Name: "default",
			}), "sandbox-ns/default")
			assert.Equal(t, descriptor.Enabled(), true)
		case v3.PolicyBindingType:
			assert.Equal(t, descriptor.ConfigKind, kind.PolicyBinding)
			assert.Equal(t, descriptor.ResourceNameFromKey(model.ConfigKey{
				Name: "workload://ns/uid-1",
			}), "workload://ns/uid-1")
		case v3.SniTrafficPolicyType:
			assert.Equal(t, descriptor.ConfigKind, kind.SniTrafficPolicy)
			assert.Equal(t, descriptor.ResourceNameFromKey(model.ConfigKey{
				Name: testGatewayNS + "/allow-all",
			}), testGatewayNS+"/allow-all")
		default:
			t.Fatalf("unexpected Agentio resource descriptor %q", descriptor.TypeURL)
		}
	}
	assert.Equal(t, counts[v3.WorkloadConfigType], 1)
	assert.Equal(t, counts[v3.PolicyBindingType], 1)
	assert.Equal(t, counts[v3.SniTrafficPolicyType], 1)

	// Callers receive their own slice and cannot corrupt subsequent registrations.
	originalFirstType := descriptors[0].TypeURL
	descriptors[0].TypeURL = "mutated"
	assert.Equal(t, AgentioResourceDescriptors()[0].TypeURL, originalFirstType)
}

// TestSniPolicyGeneratorsRegisteredInPushOrder verifies the ordering plumbing.
func TestSniPolicyGeneratorsRegisteredInPushOrder(t *testing.T) {
	assert.Equal(t, KnownOrderedTypeUrls.Contains(v3.PolicyBindingType), true)
	assert.Equal(t, KnownOrderedTypeUrls.Contains(v3.SniTrafficPolicyType), true)

	// Policies must be pushed before the bindings that reference them.
	policyIdx, bindingIdx := -1, -1
	for i, tu := range PushOrder {
		switch tu {
		case v3.SniTrafficPolicyType:
			policyIdx = i
		case v3.PolicyBindingType:
			bindingIdx = i
		}
	}
	if policyIdx < 0 || bindingIdx < 0 {
		t.Fatalf("missing types in PushOrder: policy=%d binding=%d", policyIdx, bindingIdx)
	}
	if policyIdx > bindingIdx {
		t.Fatalf("SniTrafficPolicy (%d) must be pushed before PolicyBinding (%d)", policyIdx, bindingIdx)
	}
}
