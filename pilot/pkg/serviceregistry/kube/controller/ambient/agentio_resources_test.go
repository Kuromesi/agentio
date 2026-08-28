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
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/pkg/workloadapi"
)

type agentioResourceTestModel struct {
	key      model.ConfigKey
	name     string
	resource proto.Message
	visible  bool
}

func (m agentioResourceTestModel) ConfigKey() model.ConfigKey { return m.key }
func (m agentioResourceTestModel) ResourceName() string       { return m.name }

type trackingAgentioResourceCollection[T any] struct {
	krt.Collection[T]
	listCalls int
	getKeys   []string
}

func (c *trackingAgentioResourceCollection[T]) List() []T {
	c.listCalls++
	return c.Collection.List()
}

func (c *trackingAgentioResourceCollection[T]) GetKey(key string) *T {
	c.getKeys = append(c.getKeys, key)
	return c.Collection.GetKey(key)
}

type configUpdateRecorder struct {
	model.XDSUpdater
	requests []*model.PushRequest
}

func (r *configUpdateRecorder) ConfigUpdate(request *model.PushRequest) {
	r.requests = append(r.requests, request)
}

func TestAgentioResourceProvidersAndDescriptors(t *testing.T) {
	descriptorTypes := sets.New[string]()
	for _, descriptor := range xds.AgentioResourceDescriptors() {
		descriptorTypes.Insert(descriptor.TypeURL)
	}
	assert.Equal(t, descriptorTypes, sets.New(xdsmodel.SniTrafficPolicyType))
}

func TestAgentioResourcesForProxy(t *testing.T) {
	policyOne := &extensions.SniTrafficPolicy{}
	policyTwo := &extensions.SniTrafficPolicy{}
	policies := []agentio.BindablePolicy{
		{Name: "ns/one", TypeURL: xdsmodel.SniTrafficPolicyType, ConfigKind: kind.SniTrafficPolicy, Resource: policyOne},
		{Name: "ns/two", TypeURL: xdsmodel.SniTrafficPolicyType, ConfigKind: kind.SniTrafficPolicy, Resource: policyTwo},
	}
	mock := krttest.NewMock(t, slices.Map(policies, func(policy agentio.BindablePolicy) any { return policy }))
	a := &index{bindablePolicies: krttest.GetMockCollection[agentio.BindablePolicy](mock)}

	requested := sets.New(model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns/one"})
	got := a.AgentioResourcesForProxy(nil, xdsmodel.SniTrafficPolicyType, requested)
	assert.Equal(t, len(got), 1)
	assert.Equal(t, got[0].Name, "ns/one")
	if got[0].Resource != policyOne {
		t.Error("filtered policy payload pointer was not preserved")
	}
	assert.Equal(t, a.AgentioResourcesForProxy(nil, "type.googleapis.com/unknown", nil), nil)
}

func TestAgentioResourceProviderUsesKeyedLookup(t *testing.T) {
	wanted := agentioResourceTestModel{
		key:  model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "wanted"},
		name: "wanted", resource: &extensions.SniTrafficPolicy{}, visible: true,
	}
	unrelated := agentioResourceTestModel{
		key:  model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "unrelated"},
		name: "unrelated", resource: &extensions.SniTrafficPolicy{}, visible: true,
	}
	mock := krttest.NewMock(t, []any{wanted, unrelated})
	tracked := &trackingAgentioResourceCollection[agentioResourceTestModel]{
		Collection: krttest.GetMockCollection[agentioResourceTestModel](mock),
	}
	provider := collectAgentioResources(
		func(*index) krt.Collection[agentioResourceTestModel] { return tracked },
		func(key model.ConfigKey) string { return key.Name },
		func(item agentioResourceTestModel) string { return item.ResourceName() },
		func(item agentioResourceTestModel) proto.Message { return item.resource },
		nil,
	)

	got := provider(&index{}, nil, sets.New(wanted.ConfigKey()))
	assert.Equal(t, tracked.listCalls, 0)
	assert.Equal(t, tracked.getKeys, []string{"wanted"})
	assert.Equal(t, len(got), 1)
}

func TestWorkloadExtensionsForProxyPublishesPerTypePolicyReference(t *testing.T) {
	const uid = "cluster//Pod/ns/pod"
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{Uid: uid, Name: "pod", Namespace: "ns"},
		Source:   kind.Pod,
	}
	references := agentio.WorkloadPolicyReferences{
		Name: uid,
		References: []*extensions.PolicyReference{
			{TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{"ns/policy"}},
			{TypeUrl: "type.googleapis.com/example.extensions.v1.UnsupportedPolicy", ResourceNames: []string{"ns/ignored"}},
		},
	}
	mock := krttest.NewMock(t, []any{workload, references})
	a := &index{
		workloads: workloadsCollection{
			Collection: krttest.GetMockCollection[model.WorkloadInfo](mock),
		},
		workloadPolicyReferences: krttest.GetMockCollection[agentio.WorkloadPolicyReferences](mock),
	}
	proxy := &model.Proxy{Metadata: &model.NodeMetadata{
		MetadataDiscovery:         ptr.Of(model.StringBool(true)),
		PolicyRuntimeCapabilities: []string{agentio.SniTrafficPolicyCapability},
	}}

	got := a.WorkloadExtensionsForProxy(proxy, &workloadapi.Workload{Uid: uid})
	assert.Equal(t, len(got), 1)
	assert.Equal(t, got[0].GetName(), agentio.SniTrafficPolicyReferenceExtensionName)
	assert.Equal(t, got[0].GetConfig().GetTypeUrl(), agentio.PolicyReferenceTypeURL)
	decoded := &extensions.PolicyReference{}
	if err := got[0].GetConfig().UnmarshalTo(decoded); err != nil {
		t.Fatal(err)
	}
	want := &extensions.PolicyReference{
		TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{"ns/policy"},
	}
	if !proto.Equal(decoded, want) {
		t.Fatalf("decoded references = %v, want %v", decoded, want)
	}

	proxy.Metadata.MetadataDiscovery = ptr.Of(model.StringBool(false))
	assert.Equal(t, len(a.WorkloadExtensionsForProxy(proxy, &workloadapi.Workload{Uid: uid})), 0)
}

func TestWorkloadExtensionsForProxyMarksPodWithoutPolicies(t *testing.T) {
	const uid = "cluster//Pod/ns/unbound"
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{Uid: uid, Name: "unbound", Namespace: "ns"},
		Source:   kind.Pod,
	}
	mock := krttest.NewMock(t, []any{workload})
	a := &index{
		workloads: workloadsCollection{
			Collection: krttest.GetMockCollection[model.WorkloadInfo](mock),
		},
		workloadPolicyReferences: krttest.GetMockCollection[agentio.WorkloadPolicyReferences](mock),
	}
	proxy := &model.Proxy{Metadata: &model.NodeMetadata{
		MetadataDiscovery:         ptr.Of(model.StringBool(true)),
		PolicyRuntimeCapabilities: []string{agentio.SniTrafficPolicyCapability},
	}}

	got := a.WorkloadExtensionsForProxy(proxy, workload.Workload)
	if len(got) != 1 {
		t.Fatalf("extensions = %d, want one empty SNI policy marker", len(got))
	}
	decoded := &extensions.PolicyReference{}
	if err := got[0].GetConfig().UnmarshalTo(decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetTypeUrl() != xdsmodel.SniTrafficPolicyType || len(decoded.GetResourceNames()) != 0 {
		t.Fatalf("decoded reference = %v, want empty %s reference", decoded, xdsmodel.SniTrafficPolicyType)
	}
}

func TestWorkloadExtensionsForProxySkipsNonPodWorkload(t *testing.T) {
	const uid = "cluster/discovery.k8s.io/EndpointSlice/ns/shared/10.0.0.1"
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{Uid: uid, Name: "shared", Namespace: "ns"},
		Source:   kind.EndpointSlice,
	}
	mock := krttest.NewMock(t, []any{workload})
	a := &index{
		workloads: workloadsCollection{
			Collection: krttest.GetMockCollection[model.WorkloadInfo](mock),
		},
		workloadPolicyReferences: krttest.GetMockCollection[agentio.WorkloadPolicyReferences](mock),
	}
	proxy := &model.Proxy{Metadata: &model.NodeMetadata{
		MetadataDiscovery:         ptr.Of(model.StringBool(true)),
		PolicyRuntimeCapabilities: []string{agentio.SniTrafficPolicyCapability},
	}}

	assert.Equal(t, len(a.WorkloadExtensionsForProxy(proxy, workload.Workload)), 0)
}

func TestPushWorkloadPolicyReferencesXdsIncludesNewPolicies(t *testing.T) {
	oldReferences := agentio.WorkloadPolicyReferences{
		Name: "cluster//Pod/ns/pod",
		References: []*extensions.PolicyReference{{
			TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{"ns/existing"},
		}},
	}
	newReferences := oldReferences
	newReferences.References = []*extensions.PolicyReference{{
		TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{"ns/existing", "ns/new"},
	}}
	recorder := &configUpdateRecorder{}

	PushWorkloadPolicyReferencesXds(recorder)([]krt.Event[agentio.WorkloadPolicyReferences]{
		{Event: controllers.EventUpdate, Old: &oldReferences, New: &newReferences},
	})

	if len(recorder.requests) != 1 {
		t.Fatalf("ConfigUpdate calls = %d, want 1", len(recorder.requests))
	}
	request := recorder.requests[0]
	assert.Equal(t, request.AddressesUpdated, sets.New(newReferences.ResourceName()))
	assert.Equal(t, request.ConfigsUpdated, sets.New(
		model.ConfigKey{Kind: kind.Address, Name: newReferences.ResourceName()},
		model.ConfigKey{Kind: kind.SniTrafficPolicy, Name: "ns/new"},
	))
}

func TestPushWorkloadPolicyReferencesXdsPushesAddressWhenLastReferenceIsRemoved(t *testing.T) {
	oldReferences := agentio.WorkloadPolicyReferences{
		Name: "cluster//Pod/ns/pod",
		References: []*extensions.PolicyReference{{
			TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{"ns/old"},
		}},
	}
	recorder := &configUpdateRecorder{}

	PushWorkloadPolicyReferencesXds(recorder)([]krt.Event[agentio.WorkloadPolicyReferences]{
		{Event: controllers.EventDelete, Old: &oldReferences},
	})

	if len(recorder.requests) != 1 {
		t.Fatalf("ConfigUpdate calls = %d, want 1", len(recorder.requests))
	}
	request := recorder.requests[0]
	assert.Equal(t, request.AddressesUpdated, sets.New(oldReferences.ResourceName()))
	assert.Equal(t, request.ConfigsUpdated, sets.New(
		model.ConfigKey{Kind: kind.Address, Name: oldReferences.ResourceName()},
	))
}
