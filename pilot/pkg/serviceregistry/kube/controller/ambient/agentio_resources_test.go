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

package ambient

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"
)

type agentioResourceTestModel struct {
	key      model.ConfigKey
	name     string
	resource proto.Message
	visible  bool
}

type trackingAgentioResourceCollection[T any] struct {
	krt.Collection[T]
	listCalls int
	getKeys   []string
}

type configUpdateRecorder struct {
	model.XDSUpdater
	requests []*model.PushRequest
}

func (r *configUpdateRecorder) ConfigUpdate(request *model.PushRequest) {
	r.requests = append(r.requests, request)
}

func (c *trackingAgentioResourceCollection[T]) List() []T {
	c.listCalls++
	return c.Collection.List()
}

func (c *trackingAgentioResourceCollection[T]) GetKey(key string) *T {
	c.getKeys = append(c.getKeys, key)
	return c.Collection.GetKey(key)
}

func TestAgentioResourceProvidersAndDescriptors(t *testing.T) {
	wantDescriptors := sets.New(
		xdsmodel.WorkloadConfigType,
		xdsmodel.SniTrafficPolicyType,
		xdsmodel.PolicyBindingType,
	)
	wantDedicatedProviders := sets.New(
		xdsmodel.WorkloadConfigType,
		xdsmodel.PolicyBindingType,
	)
	providerTypes := sets.New[string]()
	for typeURL := range agentioResourceProviders {
		providerTypes.Insert(typeURL)
	}
	descriptorTypes := sets.New[string]()
	for _, descriptor := range xds.AgentioResourceDescriptors() {
		descriptorTypes.Insert(descriptor.TypeURL)
	}
	assert.Equal(t, providerTypes, wantDedicatedProviders)
	assert.Equal(t, descriptorTypes, wantDescriptors)
}

func (m agentioResourceTestModel) ConfigKey() model.ConfigKey {
	return m.key
}

func (m agentioResourceTestModel) ResourceName() string {
	return m.name
}

func TestAgentioResourcesForProxy(t *testing.T) {
	const ns = "ns"

	bindingFor := func(name string) model.PolicyBinding {
		return model.PolicyBinding{
			Name: model.PolicyBindingResourceName(ns, name),
			Binding: &extensions.PolicyBinding{
				TargetRef: &extensions.PolicyBinding_Workload{
					Workload: &extensions.WorkloadReference{Namespace: ns, Name: name},
				},
			},
		}
	}
	bindings := []model.PolicyBinding{bindingFor("a"), bindingFor("b")}
	bindingsByResourceName := map[string]model.PolicyBinding{
		bindings[0].Name: bindings[0],
		bindings[1].Name: bindings[1],
	}

	policyOne := &extensions.SniTrafficPolicy{}
	policyTwo := &extensions.SniTrafficPolicy{}
	policyOther := &extensions.SniTrafficPolicy{}
	policies := []agentio.BindablePolicy{
		{Name: "ns/one", TypeURL: xdsmodel.SniTrafficPolicyType, ConfigKind: kind.SniTrafficPolicy, Resource: policyOne},
		{Name: "ns/two", TypeURL: xdsmodel.SniTrafficPolicyType, ConfigKind: kind.SniTrafficPolicy, Resource: policyTwo},
		{Name: "other/one", TypeURL: xdsmodel.SniTrafficPolicyType, ConfigKind: kind.SniTrafficPolicy, Resource: policyOther},
	}
	inputs := slices.Map(bindings, func(b model.PolicyBinding) any { return b })
	inputs = append(inputs, slices.Map(policies, func(p agentio.BindablePolicy) any { return p })...)
	mock := krttest.NewMock(t, inputs)
	a := &index{
		policyBindings:   krttest.GetMockCollection[model.PolicyBinding](mock),
		bindablePolicies: krttest.GetMockCollection[agentio.BindablePolicy](mock),
	}

	t.Run("projects registered types and preserves protobuf pointers", func(t *testing.T) {
		bindings := a.AgentioResourcesForProxy(nil, xdsmodel.PolicyBindingType, nil)
		assert.Equal(t, len(bindings), 2)
		bindingsByName := make(map[string]model.AgentioResource, len(bindings))
		for _, binding := range bindings {
			bindingsByName[binding.Name] = binding
		}
		for _, name := range []string{"a", "b"} {
			resourceName := model.PolicyBindingResourceName(ns, name)
			got, found := bindingsByName[resourceName]
			assert.Equal(t, found, true)
			if got.Resource != bindingsByResourceName[resourceName].Binding {
				t.Errorf("binding %q payload pointer was not preserved", resourceName)
			}
		}

		gotPolicies := a.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, nil)
		assert.Equal(t, len(gotPolicies), 3)
		policiesByName := make(map[string]model.AgentioResource, len(gotPolicies))
		for _, policy := range gotPolicies {
			policiesByName[policy.Name] = policy
		}
		if policiesByName["ns/one"].Resource != policyOne {
			t.Error("ns/one payload pointer was not preserved")
		}
		if policiesByName["ns/two"].Resource != policyTwo {
			t.Error("ns/two payload pointer was not preserved")
		}
		if policiesByName["other/one"].Resource != policyOther {
			t.Error("other/one payload pointer was not preserved")
		}
	})

	t.Run("requested filters on name and namespace", func(t *testing.T) {
		requested := sets.New(model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns/one"})
		got := a.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, requested)
		assert.Equal(t, len(got), 1)
		assert.Equal(t, got[0].Name, "ns/one")
		if got[0].Resource != policyOne {
			t.Error("filtered policy payload pointer was not preserved")
		}
	})

	t.Run("unknown requested key returns nothing", func(t *testing.T) {
		requested := sets.New(model.ConfigKey{Kind: kind.PolicyBinding, Name: "workload://ns/unknown"})
		assert.Equal(t, len(a.AgentioResourcesForProxy(nil, xdsmodel.PolicyBindingType, requested)), 0)
	})

	t.Run("unknown type URL returns nil", func(t *testing.T) {
		assert.Equal(t, a.AgentioResourcesForProxy(nil, "type.googleapis.com/unknown", nil), nil)
	})

	t.Run("nil registered collections return nil", func(t *testing.T) {
		empty := &index{}
		assert.Equal(t, empty.AgentioResourcesForProxy(nil, xdsmodel.PolicyBindingType, nil), nil)
		assert.Equal(t, empty.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, nil), nil)
		assert.Equal(t, empty.AgentioResourcesForProxy(nil, xdsmodel.WorkloadConfigType, nil), nil)
	})

	t.Run("invalid projections and invisible resources are omitted", func(t *testing.T) {
		var typedNil *extensions.SniTrafficPolicy
		valid := &extensions.SniTrafficPolicy{}
		models := []agentioResourceTestModel{
			{name: "", resource: &extensions.SniTrafficPolicy{}, visible: true},
			{name: "untyped-nil", resource: nil, visible: true},
			{name: "typed-nil", resource: typedNil, visible: true},
			{name: "hidden", resource: &extensions.SniTrafficPolicy{}, visible: false},
			{name: "valid", resource: valid, visible: true},
		}
		modelMock := krttest.NewMock(t, slices.Map(models, func(m agentioResourceTestModel) any { return m }))
		collection := krttest.GetMockCollection[agentioResourceTestModel](modelMock)
		provider := collectAgentioResources(
			func(*index) krt.Collection[agentioResourceTestModel] { return collection },
			func(key model.ConfigKey) string { return key.Name },
			func(m agentioResourceTestModel) string { return m.ResourceName() },
			func(m agentioResourceTestModel) proto.Message { return m.resource },
			func(_ *index, proxy *model.Proxy, m agentioResourceTestModel) bool {
				return proxy != nil && m.visible
			},
		)

		got := provider(a, &model.Proxy{}, nil)
		assert.Equal(t, len(got), 1)
		assert.Equal(t, got[0].Name, "valid")
		if got[0].Resource != valid {
			t.Error("valid projected payload pointer was not preserved")
		}
	})

	t.Run("requested resources use keyed lookup", func(t *testing.T) {
		wanted := agentioResourceTestModel{
			key:      model.ConfigKey{Kind: kind.PolicyBinding, Name: "wanted"},
			name:     "wanted",
			resource: &extensions.PolicyBinding{},
			visible:  true,
		}
		unrelated := agentioResourceTestModel{
			key:      model.ConfigKey{Kind: kind.PolicyBinding, Name: "unrelated"},
			name:     "unrelated",
			resource: &extensions.PolicyBinding{},
			visible:  true,
		}
		modelMock := krttest.NewMock(t, []any{wanted, unrelated})
		tracked := &trackingAgentioResourceCollection[agentioResourceTestModel]{
			Collection: krttest.GetMockCollection[agentioResourceTestModel](modelMock),
		}
		provider := collectAgentioResources(
			func(*index) krt.Collection[agentioResourceTestModel] { return tracked },
			func(key model.ConfigKey) string { return key.Name },
			func(m agentioResourceTestModel) string { return m.ResourceName() },
			func(m agentioResourceTestModel) proto.Message { return m.resource },
			nil,
		)

		got := provider(a, nil, sets.New(wanted.ConfigKey()))
		assert.Equal(t, tracked.listCalls, 0)
		assert.Equal(t, tracked.getKeys, []string{"wanted"})
		assert.Equal(t, len(got), 1)
		assert.Equal(t, got[0].Name, "wanted")
	})
}

// TestSniPoliciesFlagOffInert pins the flag-off provider contract. Both final
// collections stay nil, so callers cannot distinguish "feature off" from a
// spuriously empty push.
func TestSniPoliciesFlagOffInert(t *testing.T) {
	a := &index{}

	assert.Equal(t, a.policyBindings, nil)
	assert.Equal(t, a.bindablePolicies, nil)
	assert.Equal(t, a.AgentioResourcesForProxy(nil, xdsmodel.PolicyBindingType, nil), nil)
	assert.Equal(t, a.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, nil), nil)

	// The nil guard must run before requested-resource filtering.
	requested := sets.New(model.ConfigKey{Kind: kind.PolicyBinding, Name: "anything"})
	assert.Equal(t, a.AgentioResourcesForProxy(nil, xdsmodel.PolicyBindingType, requested), nil)
	assert.Equal(t, a.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, requested), nil)
}

func TestWorkloadConfigAgentioResourcesForProxy(t *testing.T) {
	system := model.WorkloadConfig{
		Namespace: "agentio-system", Name: "system", Config: &extensions.WorkloadConfig{},
	}
	sameNamespace := model.WorkloadConfig{
		Namespace: "sandbox-ns", Name: "same", Config: &extensions.WorkloadConfig{},
	}
	otherNamespace := model.WorkloadConfig{
		Namespace: "other-ns", Name: "other", Config: &extensions.WorkloadConfig{},
	}
	mock := krttest.NewMock(t, []any{system, sameNamespace, otherNamespace})
	a := &index{
		SystemNamespace: "agentio-system",
		workloadConfigs: krttest.GetMockCollection[model.WorkloadConfig](mock),
	}
	nonDedicatedProxy := &model.Proxy{
		Labels:   map[string]string{},
		Metadata: &model.NodeMetadata{Namespace: "sandbox-ns"},
	}
	dedicatedProxy := &model.Proxy{
		Labels: map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
		Metadata: &model.NodeMetadata{
			Namespace: "sandbox-ns",
			Labels:    map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
		},
	}

	assertResources := func(t *testing.T, got []model.AgentioResource, want map[string]proto.Message) {
		t.Helper()
		assert.Equal(t, len(got), len(want))
		for _, resource := range got {
			payload, found := want[resource.Name]
			assert.Equal(t, found, true)
			if resource.Resource != payload {
				t.Errorf("resource %q payload pointer was not preserved", resource.Name)
			}
		}
	}

	t.Run("non-dedicated proxy receives all configs", func(t *testing.T) {
		got := a.AgentioResourcesForProxy(nonDedicatedProxy, xdsmodel.WorkloadConfigType, nil)
		assertResources(t, got, map[string]proto.Message{
			system.ResourceName():         system.Config,
			sameNamespace.ResourceName():  sameNamespace.Config,
			otherNamespace.ResourceName(): otherNamespace.Config,
		})
	})

	t.Run("dedicated sandbox proxy receives system and same namespace configs", func(t *testing.T) {
		got := a.AgentioResourcesForProxy(dedicatedProxy, xdsmodel.WorkloadConfigType, nil)
		assertResources(t, got, map[string]proto.Message{
			system.ResourceName():        system.Config,
			sameNamespace.ResourceName(): sameNamespace.Config,
		})
	})

	t.Run("requested filter selects same namespace config", func(t *testing.T) {
		requested := sets.New(sameNamespace.ConfigKey())
		got := a.AgentioResourcesForProxy(dedicatedProxy, xdsmodel.WorkloadConfigType, requested)
		assertResources(t, got, map[string]proto.Message{
			sameNamespace.ResourceName(): sameNamespace.Config,
		})
	})
}

func TestPushPolicyBindingsXdsIncludesNewPolicyReferences(t *testing.T) {
	oldBinding := model.PolicyBinding{
		Name: "workload://ns/pod",
		Binding: &extensions.PolicyBinding{PolicyRefs: map[string]*extensions.PolicyReference{
			xdsmodel.SniTrafficPolicyType: {ResourceNames: []string{"ns/existing"}},
		}},
	}
	newBinding := model.PolicyBinding{
		Name: oldBinding.Name,
		Binding: &extensions.PolicyBinding{PolicyRefs: map[string]*extensions.PolicyReference{
			xdsmodel.SniTrafficPolicyType: {ResourceNames: []string{"ns/existing", "ns/new"}},
		}},
	}
	recorder := &configUpdateRecorder{}

	PushPolicyBindingsXds(recorder)([]krt.Event[model.PolicyBinding]{
		{Event: controllers.EventUpdate, Old: &oldBinding, New: &newBinding},
	})

	if len(recorder.requests) != 1 {
		t.Fatalf("ConfigUpdate calls = %d, want 1", len(recorder.requests))
	}
	want := sets.New(
		newBinding.ConfigKey(),
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns/new"},
	)
	assert.Equal(t, recorder.requests[0].ConfigsUpdated, want)
}
