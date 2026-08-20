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
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/workloadapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const policyBindingTestCluster = "cluster-0"

func sniTestWorkloadKey(name, namespace string) string {
	return model.PolicyBindingResourceName(namespace, name)
}

// sniTestWorkload carries the namespace and pod name published in the
// PolicyBinding workload reference.
func sniTestWorkload(name, namespace string, labels map[string]string) model.WorkloadInfo {
	return model.WorkloadInfo{
		Workload: &workloadapi.Workload{
			Uid:       policyBindingTestCluster + "//Pod/" + namespace + "/" + name,
			Name:      name,
			Namespace: namespace,
			ClusterId: policyBindingTestCluster,
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
		Resource: &extensions.SniTrafficPolicy{
			Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "example.com")},
		},
	}
}

// runPolicyBindingCollection drives the real collection over static mock inputs and
// returns the emitted bindings keyed by complete xDS resource name.
func runPolicyBindingCollection(
	t test.Failer,
	workloads []model.WorkloadInfo,
	policies []BindablePolicy,
) (krt.Collection[model.PolicyBinding], map[string]model.PolicyBinding) {
	t.Helper()
	inputs := make([]any, 0, len(workloads)+len(policies))
	for _, w := range workloads {
		inputs = append(inputs, w)
	}
	for _, policy := range policies {
		inputs = append(inputs, policy)
	}
	mock := krttest.NewMock(t, inputs)
	opts := krt.NewOptionsBuilder(test.NewStop(t), "", krt.GlobalDebugHandler)
	bindablePolicies := krttest.GetMockCollection[BindablePolicy](mock)
	c := &Controller{
		bindablePolicies:  bindablePolicies,
		policyAttachments: newPolicyAttachmentsCollection(bindablePolicies, opts),
	}
	col := c.BuildPolicyBindingCollection(krttest.GetMockCollection[model.WorkloadInfo](mock), opts)
	if c.PolicyBindings() != col {
		t.Fatal("controller did not retain the final PolicyBinding collection")
	}
	col.WaitUntilSynced(test.NewStop(t))

	byWorkload := map[string]model.PolicyBinding{}
	for _, b := range col.List() {
		// Every emitted binding must be valid and carry the workload identity
		// encoded by its xDS resource name.
		workload := b.Binding.GetWorkload()
		assert.Equal(t, b.Name, model.PolicyBindingResourceName(workload.GetNamespace(), workload.GetName()))
		byWorkload[b.Name] = b
	}
	return col, byWorkload
}

// resourceNamesFor returns the resource_names of the SNI policy reference.
// It returns nil when the binding carries no SNI policy reference.
func resourceNamesFor(t test.Failer, b model.PolicyBinding) []string {
	t.Helper()
	ref := b.Binding.GetPolicyRefs()[xdsmodel.SniTrafficPolicyType]
	if ref == nil {
		return nil
	}
	return ref.GetResourceNames()
}

func TestPolicyBindingCollection(t *testing.T) {
	const ns = "ns"
	keyFor := func(name, namespace string) string {
		return sniTestWorkloadKey(name, namespace)
	}

	t.Run("orders by descending priority", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, map[string]string{"app": "a"})},
			[]BindablePolicy{
				// Deliberately inserted low-priority-first so a missing sort shows up.
				sniBindablePolicy(ns, "low", 1, map[string]string{"app": "a"}),
				sniBindablePolicy(ns, "high", 100, map[string]string{"app": "a"}),
				sniBindablePolicy(ns, "mid", 50, map[string]string{"app": "a"}),
			})

		assert.Equal(t, len(got), 1)
		b := got[keyFor("pod", ns)]
		assert.Equal(t, resourceNamesFor(t, b), []string{"ns/high", "ns/mid", "ns/low"})
	})

	t.Run("equal priority tie-breaks on ascending name", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, map[string]string{"app": "a"})},
			[]BindablePolicy{
				sniBindablePolicy(ns, "zebra", 7, map[string]string{"app": "a"}),
				sniBindablePolicy(ns, "alpha", 7, map[string]string{"app": "a"}),
				sniBindablePolicy(ns, "mango", 7, map[string]string{"app": "a"}),
			})

		b := got[keyFor("pod", ns)]
		assert.Equal(t, resourceNamesFor(t, b), []string{"ns/alpha", "ns/mango", "ns/zebra"})
	})

	t.Run("equal priority orders by creation time before name", func(t *testing.T) {
		older := sniBindablePolicy(ns, "zebra", 7, map[string]string{"app": "a"})
		older.CreationTime = time.Unix(1, 0)
		newer := sniBindablePolicy(ns, "alpha", 7, map[string]string{"app": "a"})
		newer.CreationTime = time.Unix(2, 0)

		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, map[string]string{"app": "a"})},
			[]BindablePolicy{newer, older})

		b := got[keyFor("pod", ns)]
		assert.Equal(t, resourceNamesFor(t, b), []string{"ns/zebra", "ns/alpha"})
	})

	t.Run("priority dominates name", func(t *testing.T) {
		// "zebra" sorts last by name but wins on priority: proves priority is the
		// primary key rather than the sort merely being alphabetical.
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, nil)},
			[]BindablePolicy{
				sniBindablePolicy(ns, "alpha", 1, nil),
				sniBindablePolicy(ns, "zebra", 2, nil),
			})

		b := got[keyFor("pod", ns)]
		assert.Equal(t, resourceNamesFor(t, b), []string{"ns/zebra", "ns/alpha"})
	})

	t.Run("unmatched workload still gets an empty binding", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, map[string]string{"app": "a"})},
			[]BindablePolicy{
				sniBindablePolicy(ns, "other", 1, map[string]string{"app": "b"}),
			})

		assert.Equal(t, len(got), 1)
		b, found := got[keyFor("pod", ns)]
		assert.Equal(t, found, true)
		// The empty binding is the point: it means "no configured policy",
		// which is distinct from no binding at all.
		assert.Equal(t, len(b.Binding.GetPolicyRefs()), 0)
		assert.Equal(t, b.Binding.GetWorkload().GetNamespace(), ns)
		assert.Equal(t, b.Binding.GetWorkload().GetName(), "pod")
	})

	t.Run("no policies at all still yields a binding per workload", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{
				sniTestWorkload("a", ns, nil),
				sniTestWorkload("b", ns, nil),
			},
			nil)

		assert.Equal(t, len(got), 2)
		for _, name := range []string{"a", "b"} {
			b, found := got[keyFor(name, ns)]
			assert.Equal(t, found, true)
			assert.Equal(t, len(b.Binding.GetPolicyRefs()), 0)
		}
	})

	t.Run("empty selector matches namespace but not other namespaces", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{
				sniTestWorkload("in", ns, map[string]string{"app": "a"}),
				sniTestWorkload("also-in", ns, nil),
				sniTestWorkload("out", "other-ns", map[string]string{"app": "a"}),
			},
			[]BindablePolicy{
				// Empty selector: everything in "ns", nothing outside it.
				sniBindablePolicy(ns, "catch-all", 5, nil),
			})

		assert.Equal(t, len(got), 3)
		// Both directions asserted: in-namespace workloads are selected...
		assert.Equal(t, resourceNamesFor(t, got[keyFor("in", ns)]), []string{"ns/catch-all"})
		assert.Equal(t, resourceNamesFor(t, got[keyFor("also-in", ns)]), []string{"ns/catch-all"})
		// ...and the out-of-namespace workload is not, yet still gets a binding.
		out := got[keyFor("out", "other-ns")]
		assert.Equal(t, len(out.Binding.GetPolicyRefs()), 0)
	})

	t.Run("policy does not cross namespaces even with matching labels", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", "other-ns", map[string]string{"app": "a"})},
			[]BindablePolicy{
				sniBindablePolicy(ns, "same-labels", 1, map[string]string{"app": "a"}),
			})

		b := got[keyFor("pod", "other-ns")]
		assert.Equal(t, len(b.Binding.GetPolicyRefs()), 0)
	})

	t.Run("global policy selects matching workloads across namespaces", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{
				sniTestWorkload("a", "ns-a", map[string]string{"app": "agent"}),
				sniTestWorkload("b", "ns-b", map[string]string{"app": "agent"}),
				sniTestWorkload("other", "ns-c", map[string]string{"app": "other"}),
			},
			[]BindablePolicy{
				sniBindablePolicy("", "global", 1, map[string]string{"app": "agent"}),
			})

		assert.Equal(t, resourceNamesFor(t, got[keyFor("a", "ns-a")]), []string{"global"})
		assert.Equal(t, resourceNamesFor(t, got[keyFor("b", "ns-b")]), []string{"global"})
		assert.Equal(t, len(got[keyFor("other", "ns-c")].Binding.GetPolicyRefs()), 0)
	})

	t.Run("emitted workload reference is pod NamespacedName", func(t *testing.T) {
		w := sniTestWorkload("pod", ns, nil)
		_, got := runPolicyBindingCollection(t, []model.WorkloadInfo{w}, nil)

		b, found := got[keyFor("pod", ns)]
		assert.Equal(t, found, true)
		assert.Equal(t, b.Name, "workload://ns/pod")
		assert.Equal(t, b.ResourceName(), model.PolicyBindingResourceName(ns, "pod"))
	})

	t.Run("ConfigKey uses complete xDS resource name", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{sniTestWorkload("pod", ns, nil)}, nil)

		b := got[keyFor("pod", ns)]
		// Must match exactly what ambientindex.go registers for the push, or the
		// generator's diff misses updates.
		assert.Equal(t, b.ConfigKey(), model.ConfigKey{
			Kind: kind.PolicyBinding,
			Name: "workload://ns/pod",
		})
	})

	t.Run("multiple workloads get independently scoped references", func(t *testing.T) {
		_, got := runPolicyBindingCollection(t,
			[]model.WorkloadInfo{
				sniTestWorkload("a", ns, map[string]string{"app": "a"}),
				sniTestWorkload("b", ns, map[string]string{"app": "b"}),
			},
			[]BindablePolicy{
				sniBindablePolicy(ns, "for-a", 3, map[string]string{"app": "a"}),
				sniBindablePolicy(ns, "for-b", 4, map[string]string{"app": "b"}),
			})

		assert.Equal(t, resourceNamesFor(t, got[keyFor("a", ns)]), []string{"ns/for-a"})
		assert.Equal(t, resourceNamesFor(t, got[keyFor("b", ns)]), []string{"ns/for-b"})
	})
}

func TestPolicyBindingCollectionGroupsMultiplePolicyTypes(t *testing.T) {
	sni := sniBindablePolicy("ns", "sni", 10, map[string]string{"app": "agent"})
	other := sniBindablePolicy("ns", "other", 5, map[string]string{"app": "agent"})
	other.TypeURL = "type.googleapis.com/example.extensions.v1.OtherPolicy"
	other.ConfigKind = kind.AuthorizationPolicy

	_, bindings := runPolicyBindingCollection(t,
		[]model.WorkloadInfo{sniTestWorkload("pod", "ns", map[string]string{"app": "agent"})},
		[]BindablePolicy{sni, other},
	)
	binding := bindings[model.PolicyBindingResourceName("ns", "pod")]
	refs := binding.Binding.GetPolicyRefs()
	assert.Equal(t, len(refs), 2)
	assert.Equal(t, refs[other.TypeURL].GetResourceNames(), []string{"ns/other"})
	assert.Equal(t, refs[xdsmodel.SniTrafficPolicyType].GetResourceNames(), []string{"ns/sni"})
}
