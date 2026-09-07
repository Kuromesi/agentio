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
	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	xdsmodel "istio.io/istio/pkg/model"
)

// WorkloadSNIPolicy is the resolved, ordered SNI payload for one direct Workload.
// Selection stays in the payload-free reference collection; keyed dependencies
// here propagate rules-only changes without rerunning selectors.
type WorkloadSNIPolicy struct {
	Name   string
	Policy *extensions.SniTrafficPolicy
}

func (p WorkloadSNIPolicy) ResourceName() string { return p.Name }
func (p WorkloadSNIPolicy) Equals(other WorkloadSNIPolicy) bool {
	return p.Name == other.Name && proto.Equal(p.Policy, other.Policy)
}

func newWorkloadSNIPoliciesCollection(
	references krt.Collection[WorkloadPolicyReferences],
	policies krt.Collection[BindablePolicy],
	opts krt.OptionsBuilder,
) krt.Collection[WorkloadSNIPolicy] {
	return krt.NewCollection(references, func(ctx krt.HandlerContext, refs WorkloadPolicyReferences) *WorkloadSNIPolicy {
		reference := policyReferenceForType(refs.References, xdsmodel.SniTrafficPolicyType)
		if len(reference.GetResourceNames()) == 0 {
			return nil
		}
		result := &extensions.SniTrafficPolicy{}
		for _, name := range reference.GetResourceNames() {
			policy := krt.FetchOne(ctx, policies, krt.FilterKey(xdsmodel.SniTrafficPolicyType+"|"+name))
			if policy == nil {
				// Attachment and payload callbacks may arrive separately. Keep the last
				// complete policy while the keyed dependency waits for the payload to
				// recover; deletion or reselection can also update the references.
				ctx.DiscardResult()
				return nil
			}
			payload, ok := policy.Resource.(*extensions.SniTrafficPolicy)
			if !ok || payload == nil {
				ctx.DiscardResult()
				return nil
			}
			for _, rule := range payload.Rules {
				result.Rules = append(result.Rules, proto.Clone(rule).(*extensions.SniRule))
			}
		}
		return &WorkloadSNIPolicy{Name: refs.Name, Policy: result}
	}, opts.WithName("WorkloadSNIPolicies")...)
}
