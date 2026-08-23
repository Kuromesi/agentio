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
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

// This test catches a regression where policy references are keyed by the old
// standalone binding resource name instead of the parent Workload's WDS resource
// name. WDS delta updates and removals are keyed by the latter.
func TestWorkloadPolicyReferencesUseWorkloadResourceName(t *testing.T) {
	workload := sniTestWorkload("pod", "ns", map[string]string{"app": "agent"})
	policy := sniBindablePolicy("ns", "sni", 10, map[string]string{"app": "agent"})
	mock := krttest.NewMock(t, []any{workload, policy})
	opts := krt.NewOptionsBuilder(test.NewStop(t), "", krt.GlobalDebugHandler)
	policies := krttest.GetMockCollection[BindablePolicy](mock)
	controller := &Controller{
		bindablePolicies:  policies,
		policyAttachments: newPolicyAttachmentsCollection(policies, opts),
	}

	collection := controller.BuildWorkloadPolicyReferencesCollection(
		krttest.GetMockCollection[model.WorkloadInfo](mock), opts)
	collection.WaitUntilSynced(test.NewStop(t))

	items := collection.List()
	assert.Equal(t, len(items), 1)
	assert.Equal(t, items[0].ResourceName(), workload.ResourceName())
	assert.Equal(t,
		policyReferenceForType(items[0].References, xdsmodel.SniTrafficPolicyType).GetResourceNames(),
		[]string{"ns/sni"})
}

// This test catches accidental coupling between policy content and workload
// WDS updates. Only selector/order/resource-name changes belong in the
// attachment projection used by this collection.
func TestWorkloadPolicyReferencesIgnorePolicyContentUpdates(t *testing.T) {
	workload := sniTestWorkload("pod", "ns", map[string]string{"app": "agent"})
	policy := sniBindablePolicy("ns", "sni", 10, map[string]string{"app": "agent"})
	opts := krt.NewOptionsBuilder(test.NewStop(t), "", krt.GlobalDebugHandler)
	policies := krt.NewStaticCollection(nil, []BindablePolicy{policy}, opts.WithName("BindablePolicies")...)
	attachments := newPolicyAttachmentsCollection(policies, opts)
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{workload}, opts.WithName("Workloads")...)
	collection := newWorkloadPolicyReferencesCollection(
		workloads, attachments, opts)
	collection.WaitUntilSynced(test.NewStop(t))

	updates := make(chan struct{}, 1)
	collection.RegisterBatch(func(events []krt.Event[WorkloadPolicyReferences]) {
		if len(events) > 0 {
			updates <- struct{}{}
		}
	}, false)

	updated := policy
	updated.Resource = sniBindablePolicy("ns", "sni", 10, map[string]string{"app": "agent"}).Resource
	updated.Resource.(*extensions.SniTrafficPolicy).Rules[0].Match.Sni = []string{"changed.example.com"}
	policies.Reset([]BindablePolicy{updated})

	select {
	case <-updates:
		t.Fatal("policy content update unexpectedly invalidated workload policy references")
	case <-time.After(200 * time.Millisecond):
	}
}
