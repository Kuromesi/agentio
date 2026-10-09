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
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// certificateWorkloads assigns Pod principals and registered gateway memberships.
func (r *Registry) certificateWorkloads(options ...krt.CollectionOption) krt.Collection[model.Workload] {
	return krt.NewCollection(r.Workloads, func(ctx krt.HandlerContext, w model.Workload) *model.Workload {
		pod := krt.FetchOne(ctx, r.Pods, krt.FilterKey(w.Namespace+"/"+w.Name))
		if pod == nil || podsource.SourceRef(r.options.ClusterID, string((*pod).UID)) != w.Source {
			return nil
		}
		name := (*pod).Labels[podsource.LabelGatewayName]
		if (*pod).UID != "" && name != "" && (*pod).Status.Phase != corev1.PodSucceeded &&
			(*pod).Status.Phase != corev1.PodFailed {
			// Gateway declarations and Pod gateway-name labels must be access-controlled.
			gateway := krt.FetchOne(ctx, r.Gateways, krt.FilterKey((*pod).Namespace+"/"+name))
			if gateway != nil && gateway.ValidateForUse() == nil {
				w.GatewayKey = gateway.ResourceName()
			}
		}
		if (*pod).Spec.ServiceAccountName != "" {
			principal, err := podsource.ServiceAccountPrincipal(
				r.options.TrustDomain,
				(*pod).Namespace,
				(*pod).Spec.ServiceAccountName,
			)
			if err != nil {
				return nil
			}
			w.Principal = principal
		}
		return &w
	}, options...)
}
