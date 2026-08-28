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
	"sort"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
)

// globalPolicyAttachmentIndexKey is deliberately non-empty. Kubernetes
// namespace names cannot contain '@', so it cannot collide with a namespaced
// policy. More importantly, using an empty reverse-index key makes live global
// policy events indistinguishable from a missing index key in some KRT index
// implementations even though initial Lookup("") succeeds.
const globalPolicyAttachmentIndexKey = "@global"

// WorkloadPolicyReferences is the control-plane-only index used to enrich a
// Workload WDS resource. It is not an xDS resource of its own.
type WorkloadPolicyReferences struct {
	// Name is the parent Workload's WDS resource name (Workload.uid).
	Name       string
	References []*extensions.PolicyReference
}

func (r WorkloadPolicyReferences) ResourceName() string { return r.Name }

func (r WorkloadPolicyReferences) Equals(other WorkloadPolicyReferences) bool {
	if r.Name != other.Name || len(r.References) != len(other.References) {
		return false
	}
	for i := range r.References {
		if !proto.Equal(r.References[i], other.References[i]) {
			return false
		}
	}
	return true
}

// buildPolicyRefs selects every bindable policy for a workload, groups them by
// xDS type, and orders each type according to its source policy API contract.
func buildPolicyRefs(
	ctx krt.HandlerContext,
	policies krt.Collection[PolicyAttachment],
	policiesByNamespace krt.Index[string, PolicyAttachment],
	workloadNamespace string,
	workloadLabels map[string]string,
) []*extensions.PolicyReference {
	selectorFilter := krt.FilterGeneric(func(a any) bool {
		return a.(PolicyAttachment).Selects(workloadNamespace, workloadLabels)
	})
	matched := krt.Fetch(ctx, policies,
		krt.FilterIndex(policiesByNamespace, workloadNamespace), selectorFilter)
	// Global policies use an empty namespace and are indexed separately. The two
	// indexed Fetch calls also give krt precise reverse dependencies: a policy
	// update no longer causes every workload in the cluster to be reconsidered.
	if workloadNamespace != "" {
		matched = append(matched, krt.Fetch(ctx, policies,
			krt.FilterIndex(policiesByNamespace, globalPolicyAttachmentIndexKey), selectorFilter)...)
	}
	if len(matched) == 0 {
		return nil
	}

	byType := make(map[string][]PolicyRef)
	for _, policy := range matched {
		byType[policy.TypeURL] = append(byType[policy.TypeURL], PolicyRef{
			ResourceName:    policy.XDSResourceName(),
			Priority:        policy.Priority,
			CreationTime:    policy.CreationTime,
			SourceName:      policy.SourceName,
			SourceNamespace: policy.SourceNamespace,
		})
	}

	typeURLs := make([]string, 0, len(byType))
	for typeURL := range byType {
		typeURLs = append(typeURLs, typeURL)
	}
	sort.Strings(typeURLs)
	result := make([]*extensions.PolicyReference, 0, len(typeURLs))
	for _, typeURL := range typeURLs {
		result = append(result, &extensions.PolicyReference{
			TypeUrl:       typeURL,
			ResourceNames: sortPolicyRefs(byType[typeURL]),
		})
	}
	return result
}

func policyReferenceForType(
	references []*extensions.PolicyReference,
	typeURL string,
) *extensions.PolicyReference {
	for _, reference := range references {
		if reference.GetTypeUrl() == typeURL {
			return reference
		}
	}
	return nil
}

func newWorkloadPolicyReferencesCollection(
	workloads krt.Collection[model.WorkloadInfo],
	policies krt.Collection[PolicyAttachment],
	opts krt.OptionsBuilder,
) krt.Collection[WorkloadPolicyReferences] {
	policiesByNamespace := krt.NewIndex(policies, "policyAttachmentsByNamespace", func(policy PolicyAttachment) []string {
		if policy.Namespace == "" {
			return []string{globalPolicyAttachmentIndexKey}
		}
		return []string{policy.Namespace}
	})
	return krt.NewManyCollection(workloads,
		workloadPolicyReferencesTransformation(policies, policiesByNamespace),
		opts.WithName("WorkloadPolicyReferences")...)
}

func workloadPolicyReferencesTransformation(
	policies krt.Collection[PolicyAttachment],
	policiesByNamespace krt.Index[string, PolicyAttachment],
) krt.TransformationMulti[model.WorkloadInfo, WorkloadPolicyReferences] {
	return func(
		ctx krt.HandlerContext, w model.WorkloadInfo,
	) []WorkloadPolicyReferences {
		if w.Source != kind.Pod || w.Workload == nil || w.ResourceName() == "" {
			return nil
		}
		namespace, name := w.Workload.GetNamespace(), w.Workload.GetName()
		if namespace == "" || name == "" {
			return nil
		}
		refs := buildPolicyRefs(ctx, policies, policiesByNamespace, namespace, w.Labels)
		if len(refs) == 0 {
			// Avoid materializing an index object for unbound Pods. WDS
			// serialization adds the capability-specific empty marker that makes
			// the no-policy state authoritative to the data plane.
			return nil
		}
		return []WorkloadPolicyReferences{{
			Name:       w.ResourceName(),
			References: refs,
		}}
	}
}

var (
	_ krt.ResourceNamer                     = WorkloadPolicyReferences{}
	_ krt.Equaler[WorkloadPolicyReferences] = WorkloadPolicyReferences{}
)
