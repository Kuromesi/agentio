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
	"fmt"
	"reflect"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/pkg/workloadapi"
)

const policyReferenceTestCluster = "cluster-0"

func sniTestWorkload(name, namespace string, labels map[string]string) model.WorkloadInfo {
	return model.WorkloadInfo{
		Workload: &workloadapi.Workload{
			Uid:       policyReferenceTestCluster + "//Pod/" + namespace + "/" + name,
			Name:      name,
			Namespace: namespace,
			ClusterId: policyReferenceTestCluster,
		},
		Labels: labels,
		Source: kind.Pod,
	}
}

func sniBindablePolicy(namespace, name string, priority int32, selector map[string]string) BindablePolicy {
	resourceName := name
	if namespace != "" {
		resourceName = namespace + "/" + name
	}
	return BindablePolicy{
		Name:            resourceName,
		TypeURL:         xdsmodel.SniTrafficPolicyType,
		ConfigKind:      kind.SniTrafficPolicy,
		Namespace:       namespace,
		Priority:        priority,
		SourceName:      name,
		SourceNamespace: namespace,
		Selector:        metav1.LabelSelector{MatchLabels: selector},
		Resource: &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
			sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "example.com"),
		}},
	}
}

func runWorkloadPolicyReferencesCollection(
	t test.Failer,
	workloads []model.WorkloadInfo,
	policies []BindablePolicy,
) (krt.Collection[WorkloadPolicyReferences], map[string]WorkloadPolicyReferences) {
	t.Helper()
	inputs := make([]any, 0, len(workloads)+len(policies))
	for _, workload := range workloads {
		inputs = append(inputs, workload)
	}
	for _, policy := range policies {
		inputs = append(inputs, policy)
	}
	mock := krttest.NewMock(t, inputs)
	opts := krt.NewOptionsBuilder(test.NewStop(t), "", krt.GlobalDebugHandler)
	bindablePolicies := krttest.GetMockCollection[BindablePolicy](mock)
	controller := &Controller{
		bindablePolicies:  bindablePolicies,
		policyAttachments: newPolicyAttachmentsCollection(bindablePolicies, opts),
	}
	collection := controller.BuildWorkloadPolicyReferencesCollection(
		krttest.GetMockCollection[model.WorkloadInfo](mock), opts)
	if controller.WorkloadPolicyReferences() != collection {
		t.Fatal("controller did not retain the workload policy reference collection")
	}
	collection.WaitUntilSynced(test.NewStop(t))

	result := make(map[string]WorkloadPolicyReferences)
	for _, item := range collection.List() {
		result[item.ResourceName()] = item
	}
	return collection, result
}

func sniReferenceNames(item WorkloadPolicyReferences) []string {
	ref := policyReferenceForType(item.References, xdsmodel.SniTrafficPolicyType)
	if ref == nil {
		return nil
	}
	return ref.GetResourceNames()
}

func TestWorkloadPolicyReferencesCollection(t *testing.T) {
	const namespace = "ns"

	t.Run("orders references using source API precedence", func(t *testing.T) {
		older := sniBindablePolicy(namespace, "zebra", 7, map[string]string{"app": "a"})
		older.CreationTime = time.Unix(1, 0)
		newer := sniBindablePolicy(namespace, "alpha", 7, map[string]string{"app": "a"})
		newer.CreationTime = time.Unix(2, 0)
		high := sniBindablePolicy(namespace, "high", 100, map[string]string{"app": "a"})
		workload := sniTestWorkload("pod", namespace, map[string]string{"app": "a"})

		_, got := runWorkloadPolicyReferencesCollection(t,
			[]model.WorkloadInfo{workload}, []BindablePolicy{newer, older, high})

		assert.Equal(t, sniReferenceNames(got[workload.ResourceName()]),
			[]string{"ns/high", "ns/zebra", "ns/alpha"})
	})

	t.Run("does not materialize workloads without references", func(t *testing.T) {
		workload := sniTestWorkload("pod", namespace, map[string]string{"app": "a"})
		_, got := runWorkloadPolicyReferencesCollection(t,
			[]model.WorkloadInfo{workload},
			[]BindablePolicy{sniBindablePolicy(namespace, "other", 1, map[string]string{"app": "b"})})

		assert.Equal(t, len(got), 0)
	})

	t.Run("empty selector stays namespace scoped", func(t *testing.T) {
		in := sniTestWorkload("in", namespace, nil)
		out := sniTestWorkload("out", "other", nil)
		_, got := runWorkloadPolicyReferencesCollection(t,
			[]model.WorkloadInfo{in, out},
			[]BindablePolicy{sniBindablePolicy(namespace, "all", 1, nil)})

		assert.Equal(t, sniReferenceNames(got[in.ResourceName()]), []string{"ns/all"})
		_, found := got[out.ResourceName()]
		assert.Equal(t, found, false)
	})

	t.Run("global selector spans namespaces", func(t *testing.T) {
		a := sniTestWorkload("a", "ns-a", map[string]string{"app": "agent"})
		b := sniTestWorkload("b", "ns-b", map[string]string{"app": "agent"})
		_, got := runWorkloadPolicyReferencesCollection(t,
			[]model.WorkloadInfo{a, b},
			[]BindablePolicy{sniBindablePolicy("", "global", 1, map[string]string{"app": "agent"})})

		assert.Equal(t, sniReferenceNames(got[a.ResourceName()]), []string{"global"})
		assert.Equal(t, sniReferenceNames(got[b.ResourceName()]), []string{"global"})
	})

	t.Run("groups future policy types without changing workload schema", func(t *testing.T) {
		workload := sniTestWorkload("pod", namespace, map[string]string{"app": "agent"})
		sni := sniBindablePolicy(namespace, "sni", 10, map[string]string{"app": "agent"})
		other := sniBindablePolicy(namespace, "other", 5, map[string]string{"app": "agent"})
		other.TypeURL = "type.googleapis.com/example.extensions.v1.OtherPolicy"
		other.ConfigKind = kind.AuthorizationPolicy

		_, got := runWorkloadPolicyReferencesCollection(t,
			[]model.WorkloadInfo{workload}, []BindablePolicy{sni, other})
		refs := got[workload.ResourceName()].References

		assert.Equal(t, policyReferenceForType(refs, sni.TypeURL).GetResourceNames(), []string{"ns/sni"})
		assert.Equal(t, policyReferenceForType(refs, other.TypeURL).GetResourceNames(), []string{"ns/other"})
		assert.Equal(t, refs[0].GetTypeUrl(), other.TypeURL)
		assert.Equal(t, refs[1].GetTypeUrl(), sni.TypeURL)
	})
}

func TestWorkloadPolicyReferencesObserveGlobalPolicyAddedAfterSync(t *testing.T) {
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "", krt.GlobalDebugHandler)
	workload := sniTestWorkload("pod", "ns", map[string]string{"app": "agent"})
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{workload}, opts.WithName("Workloads")...)
	policies := krt.NewStaticCollection(nil, []BindablePolicy{}, opts.WithName("BindablePolicies")...)
	attachments := newPolicyAttachmentsCollection(policies, opts)
	references := newWorkloadPolicyReferencesCollection(workloads, attachments, opts)
	if !references.WaitUntilSynced(stop) {
		t.Fatal("workload policy references did not sync")
	}

	policies.UpdateObject(sniBindablePolicy("", "global", 1, map[string]string{"app": "agent"}))
	retry.UntilSuccessOrFail(t, func() error {
		item := references.GetKey(workload.ResourceName())
		if item == nil {
			return fmt.Errorf("workload policy references not created")
		}
		if got := sniReferenceNames(*item); !reflect.DeepEqual(got, []string{"global"}) {
			return fmt.Errorf("global policy references = %v, want [global]", got)
		}
		return nil
	}, retry.Timeout(5*time.Second))
}

func TestWorkloadPolicyReferencesObserveGlobalSecurityProfileAddedAfterSync(t *testing.T) {
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "", krt.GlobalDebugHandler)
	workload := sniTestWorkload("pod", "ns", map[string]string{"app": "agent"})
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{workload}, opts.WithName("Workloads")...)
	profiles := krt.NewStaticCollection(nil, []*agentsv1alpha1.SecurityProfile{}, opts.WithName("SecurityProfiles")...)
	globalProfiles := krt.NewStaticCollection(nil, []*agentsv1alpha1.GlobalSecurityProfile{},
		opts.WithName("GlobalSecurityProfiles")...)
	policies := newBindablePoliciesCollection(profiles, globalProfiles, opts)
	attachments := newPolicyAttachmentsCollection(policies, opts)
	references := newWorkloadPolicyReferencesCollection(workloads, attachments, opts)
	if !references.WaitUntilSynced(stop) {
		t.Fatal("workload policy references did not sync")
	}

	globalProfiles.UpdateObject(&agentsv1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "global"},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"example.com"}, Schemes: []string{"https"}}},
			}},
		},
	})
	retry.UntilSuccessOrFail(t, func() error {
		item := references.GetKey(workload.ResourceName())
		if item == nil {
			return fmt.Errorf("workload policy references not created")
		}
		if got := sniReferenceNames(*item); !reflect.DeepEqual(got, []string{"global"}) {
			return fmt.Errorf("global policy references = %v, want [global]", got)
		}
		return nil
	}, retry.Timeout(15*time.Second))
}
