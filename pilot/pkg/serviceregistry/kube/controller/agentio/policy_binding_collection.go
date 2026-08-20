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
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
)

// buildPolicyRefs selects every bindable policy for a workload, groups
// them by xDS type, and orders each type's resource names by priority.
func buildPolicyRefs(
	ctx krt.HandlerContext,
	policies krt.Collection[BindablePolicy],
	policiesByNamespace krt.Index[string, BindablePolicy],
	workloadNamespace string,
	workloadLabels map[string]string,
) map[string]*extensions.PolicyReference {
	selectorFilter := krt.FilterGeneric(func(a any) bool {
		return a.(BindablePolicy).Selects(workloadNamespace, workloadLabels)
	})
	matched := krt.Fetch(ctx, policies,
		krt.FilterIndex(policiesByNamespace, workloadNamespace), selectorFilter)
	// Global policies use an empty namespace and are indexed separately. The two
	// indexed Fetch calls also give krt precise reverse dependencies: a policy
	// update no longer causes every workload in the cluster to be reconsidered.
	if workloadNamespace != "" {
		matched = append(matched, krt.Fetch(ctx, policies,
			krt.FilterIndex(policiesByNamespace, ""), selectorFilter)...)
	}
	if len(matched) == 0 {
		return nil
	}

	byType := make(map[string][]PolicyRef)
	for _, policy := range matched {
		if policy.TypeURL == "" || policy.Name == "" || policy.Resource == nil {
			continue
		}
		byType[policy.TypeURL] = append(byType[policy.TypeURL], PolicyRef{
			ResourceName: policy.XDSResourceName(),
			Priority:     policy.Priority,
		})
	}
	if len(byType) == 0 {
		return nil
	}

	result := make(map[string]*extensions.PolicyReference, len(byType))
	for typeURL, refs := range byType {
		result[typeURL] = &extensions.PolicyReference{ResourceNames: sortPolicyRefs(refs)}
	}
	return result
}

// PolicyBindingCollection derives exactly one model.PolicyBinding per workload.
//
// A workload with no matching policy still gets a binding, with an empty
// policy_refs map. That empty binding is meaningful: it tells the data
// plane "this workload has no configured policy", which is distinct from
// "no binding has arrived yet". Skipping such workloads would make the two
// indistinguishable on the wire.
//
// Bindings are derived from the workloads collection rather than from raw Pods
// so the namespace, name, and labels are exactly those WDS advertises.
func newPolicyBindingCollection(
	workloads krt.Collection[model.WorkloadInfo],
	policies krt.Collection[BindablePolicy],
	opts krt.OptionsBuilder,
) krt.Collection[model.PolicyBinding] {
	policiesByNamespace := krt.NewIndex(policies, "bindablePoliciesByNamespace", func(policy BindablePolicy) []string {
		return []string{policy.Namespace}
	})
	return krt.NewManyCollection(workloads, func(ctx krt.HandlerContext, w model.WorkloadInfo) []model.PolicyBinding {
		if w.Source != kind.Pod {
			return nil
		}
		namespace, name := w.Workload.GetNamespace(), w.Workload.GetName()
		if namespace == "" || name == "" {
			// A namespaced Pod without both components cannot be matched by the
			// namespace/name identity used by the gateway policy lookup ABI.
			return nil
		}
		binding := &extensions.PolicyBinding{
			TargetRef: &extensions.PolicyBinding_Workload{
				Workload: &extensions.WorkloadReference{Namespace: namespace, Name: name},
			},
			PolicyRefs: buildPolicyRefs(ctx, policies, policiesByNamespace, w.Workload.GetNamespace(), w.Labels),
		}

		return []model.PolicyBinding{{Name: model.PolicyBindingResourceName(namespace, name), Binding: binding}}
	}, opts.WithName("PolicyBindings")...)
}
