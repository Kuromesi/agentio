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
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// stripTrafficPolicy deep-copies the object and drops fields unused by the policy compiler.
func stripTrafficPolicy(obj any) (any, error) {
	switch policy := obj.(type) {
	case *agentsv1alpha1.TrafficPolicy:
		if policy == nil {
			return obj, nil
		}
		result := policy.DeepCopy()
		stripPolicyObjectMeta(&result.ObjectMeta)
		result.Status = agentsv1alpha1.TrafficPolicyStatus{}
		return result, nil
	case *agentsv1alpha1.GlobalTrafficPolicy:
		if policy == nil {
			return obj, nil
		}
		result := policy.DeepCopy()
		stripPolicyObjectMeta(&result.ObjectMeta)
		result.Status = agentsv1alpha1.TrafficPolicyStatus{}
		return result, nil
	default:
		return obj, nil
	}
}

// stripSecurityProfile removes fields not used by the security policy compiler
// before an object enters the informer cache.
func stripSecurityProfile(obj any) (any, error) {
	switch profile := obj.(type) {
	case *agentsv1alpha1.SecurityProfile:
		if profile == nil {
			return obj, nil
		}
		result := profile.DeepCopy()
		stripPolicyObjectMeta(&result.ObjectMeta)
		result.Status = agentsv1alpha1.SecurityProfileStatus{}
		return result, nil
	case *agentsv1alpha1.GlobalSecurityProfile:
		if profile == nil {
			return obj, nil
		}
		result := profile.DeepCopy()
		stripPolicyObjectMeta(&result.ObjectMeta)
		result.Status = agentsv1alpha1.SecurityProfileStatus{}
		return result, nil
	default:
		return obj, nil
	}
}

func stripPolicyObjectMeta(meta *metav1.ObjectMeta) {
	meta.ManagedFields = nil
	meta.Labels = nil
	meta.OwnerReferences = nil
	meta.Finalizers = nil
	annotations := make(map[string]string, 2)
	if value, found := meta.Annotations[agentsv1alpha1.AnnotationSandboxID]; found {
		annotations[agentsv1alpha1.AnnotationSandboxID] = value
	}
	if len(annotations) == 0 {
		meta.Annotations = nil
	} else {
		meta.Annotations = annotations
	}
}
