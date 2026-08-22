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
	"time"

	"istio.io/istio/pkg/kube/krt"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
)

// PolicyAttachment is the binding-relevant projection of a BindablePolicy.
// It deliberately excludes the protobuf resource so a rules-only policy update
// does not invalidate every workload that references the policy. The complete
// BindablePolicy collection remains the source for policy xDS resources.
type PolicyAttachment struct {
	Name      string
	TypeURL   string
	Namespace string
	Priority  int32
	// Ordering metadata is retained because changing any of these fields changes
	// the ordered policy_refs emitted for matching workloads.
	CreationTime    time.Time
	SourceName      string
	SourceNamespace string
	Selector        metav1.LabelSelector

	// selector is compiled once by the policy converter and does not participate
	// in equality; Selector is its canonical source of truth.
	selector klabels.Selector
}

func (p PolicyAttachment) ResourceName() string {
	return p.TypeURL + "|" + p.Name
}

func (p PolicyAttachment) XDSResourceName() string {
	return p.Name
}

func (p PolicyAttachment) Equals(other PolicyAttachment) bool {
	return p.Name == other.Name &&
		p.TypeURL == other.TypeURL &&
		p.Namespace == other.Namespace &&
		p.Priority == other.Priority &&
		p.CreationTime.Equal(other.CreationTime) &&
		p.SourceName == other.SourceName &&
		p.SourceNamespace == other.SourceNamespace &&
		apiequality.Semantic.DeepEqual(p.Selector, other.Selector)
}

// Selects reports whether the policy attachment applies to a workload. An
// empty policy namespace is global and an empty selector matches its scope.
func (p PolicyAttachment) Selects(namespace string, workloadLabels map[string]string) bool {
	return policySelectsWorkload(p.Namespace, p.Selector, p.selector, namespace, workloadLabels)
}

func policySelectsWorkload(
	policyNamespace string,
	selectorSpec metav1.LabelSelector,
	selector klabels.Selector,
	workloadNamespace string,
	workloadLabels map[string]string,
) bool {
	if policyNamespace != "" && policyNamespace != workloadNamespace {
		return false
	}
	if selector == nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(&selectorSpec)
		if err != nil {
			return false
		}
	}
	return selector.Matches(klabels.Set(workloadLabels))
}

func policyAttachmentFromBindablePolicy(policy BindablePolicy) *PolicyAttachment {
	// A binding must never refer to a resource the xDS provider would drop.
	if policy.Name == "" || policy.TypeURL == "" || policy.Resource == nil {
		return nil
	}
	return &PolicyAttachment{
		Name:            policy.Name,
		TypeURL:         policy.TypeURL,
		Namespace:       policy.Namespace,
		Priority:        policy.Priority,
		CreationTime:    policy.CreationTime,
		SourceName:      policy.SourceName,
		SourceNamespace: policy.SourceNamespace,
		Selector:        *policy.Selector.DeepCopy(),
		selector:        policy.selector,
	}
}

func newPolicyAttachmentsCollection(
	policies krt.Collection[BindablePolicy],
	opts krt.OptionsBuilder,
) krt.Collection[PolicyAttachment] {
	return krt.NewCollection(policies, func(_ krt.HandlerContext, policy BindablePolicy) *PolicyAttachment {
		return policyAttachmentFromBindablePolicy(policy)
	}, opts.WithName("PolicyAttachments")...)
}

var (
	_ krt.ResourceNamer             = PolicyAttachment{}
	_ krt.Equaler[PolicyAttachment] = PolicyAttachment{}
)
