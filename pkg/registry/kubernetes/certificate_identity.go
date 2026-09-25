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

package kubernetes

import (
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// Certificate identities and gateway scopes share one projection of current
// registry membership. CSR contents and xDS metadata cannot enroll a member.
func (r *Registry) certificateWorkloads(options ...krt.CollectionOption) krt.Collection[model.Workload] {
	return krt.NewCollection(r.Workloads, func(ctx krt.HandlerContext, w model.Workload) *model.Workload {
		pod := krt.FetchOne(ctx, r.Pods, krt.FilterKey(w.Namespace+"/"+w.Name))
		if pod == nil || podsource.SourceRef(r.options.ClusterID, string((*pod).UID)) != w.Source {
			return nil
		}
		member := krt.FetchOne(ctx, r.gatewayMembers, krt.FilterKey(w.Source.Key))
		if member != nil {
			if member.Conflict {
				// Ambiguous membership prevents issuance, not network discovery.
				return &w
			}
			gateway := krt.FetchOne(ctx, r.Gateways, krt.FilterKey(member.GatewayKey))
			if gateway == nil || gateway.ValidateForUse() != nil {
				return &w
			}
			w.GatewayKey = member.GatewayKey
		}
		// Certificate naming is independent of gateway membership. Instances
		// sharing this logical principal are distinguished by SourceRef.
		if (*pod).Spec.ServiceAccountName != "" {
			principal, err := podsource.ServiceAccountPrincipal(r.options.TrustDomain, (*pod).Namespace, (*pod).Spec.ServiceAccountName)
			if err != nil {
				return nil
			}
			w.Principal = principal
		}
		return &w
	}, options...)
}
