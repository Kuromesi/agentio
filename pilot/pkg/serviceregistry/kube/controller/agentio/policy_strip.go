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
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/api/annotation"
)

// stripTrafficPolicyUnusedFields removes object fields that are not consumed by
// the Agentio TrafficPolicy controllers. The policy spec is preserved as-is.
func stripTrafficPolicyUnusedFields(obj any) (any, error) {
	switch policy := obj.(type) {
	case *agentsv1alpha1.TrafficPolicy:
		if policy == nil {
			return obj, nil
		}
		stripPolicyObjectMeta(&policy.ObjectMeta, true)
		policy.Status = agentsv1alpha1.TrafficPolicyStatus{}
	case *agentsv1alpha1.GlobalTrafficPolicy:
		if policy == nil {
			return obj, nil
		}
		stripPolicyObjectMeta(&policy.ObjectMeta, true)
		policy.Status = agentsv1alpha1.TrafficPolicyStatus{}
	}
	return obj, nil
}

// stripSecurityProfileUnusedFields removes object fields that are not consumed
// by the Agentio SecurityProfile controllers. The profile spec is preserved as-is.
func stripSecurityProfileUnusedFields(obj any) (any, error) {
	switch profile := obj.(type) {
	case *agentsv1alpha1.SecurityProfile:
		if profile == nil {
			return obj, nil
		}
		stripPolicyObjectMeta(&profile.ObjectMeta, false)
		profile.Status = agentsv1alpha1.SecurityProfileStatus{}
	case *agentsv1alpha1.GlobalSecurityProfile:
		if profile == nil {
			return obj, nil
		}
		stripPolicyObjectMeta(&profile.ObjectMeta, false)
		profile.Status = agentsv1alpha1.SecurityProfileStatus{}
	}
	return obj, nil
}

func stripPolicyObjectMeta(meta *metav1.ObjectMeta, keepDryRun bool) {
	meta.ManagedFields = nil
	meta.Labels = nil
	meta.OwnerReferences = nil
	meta.Finalizers = nil

	if keepDryRun {
		if value, found := meta.Annotations[annotation.IoIstioDryRun.Name]; found {
			meta.Annotations = map[string]string{annotation.IoIstioDryRun.Name: value}
			return
		}
	}
	meta.Annotations = nil
}
