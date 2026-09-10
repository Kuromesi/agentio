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

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func newTrafficPolicyModels(
	trafficPolicyObjects krt.Collection[*agentsv1alpha1.TrafficPolicy],
	globalTrafficObjects krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy],
	derivedOptions func(string) []krt.CollectionOption,
) krt.Collection[model.TrafficPolicy] {
	namespacedTraffic := krt.NewCollection(trafficPolicyObjects,
		func(_ krt.HandlerContext, policy *agentsv1alpha1.TrafficPolicy) *model.TrafficPolicy {
			return trafficPolicyModel(policy.ObjectMeta, &policy.Spec, false)
		}, derivedOptions("namespaced-traffic-policies")...)
	globalTraffic := krt.NewCollection(globalTrafficObjects,
		func(_ krt.HandlerContext, policy *agentsv1alpha1.GlobalTrafficPolicy) *model.TrafficPolicy {
			return trafficPolicyModel(policy.ObjectMeta, &policy.Spec, true)
		}, derivedOptions("global-traffic-policies")...)
	// TrafficPolicy.ResourceName prefixes namespaced and global policies
	// differently, so the two key spaces cannot collide in the join.
	return krt.JoinCollection(
		[]krt.Collection[model.TrafficPolicy]{namespacedTraffic, globalTraffic},
		derivedOptions("traffic-policies")...)
}

func newSecurityProfileModels(
	securityProfileObjects krt.Collection[*agentsv1alpha1.SecurityProfile],
	globalSecurityObjects krt.Collection[*agentsv1alpha1.GlobalSecurityProfile],
	derivedOptions func(string) []krt.CollectionOption,
) krt.Collection[model.SecurityProfile] {
	namespacedSecurity := krt.NewCollection(securityProfileObjects,
		func(_ krt.HandlerContext, profile *agentsv1alpha1.SecurityProfile) *model.SecurityProfile {
			return securityProfileModel(profile.ObjectMeta, &profile.Spec, false)
		}, derivedOptions("namespaced-security-profiles")...)
	globalSecurity := krt.NewCollection(globalSecurityObjects,
		func(_ krt.HandlerContext, profile *agentsv1alpha1.GlobalSecurityProfile) *model.SecurityProfile {
			return securityProfileModel(profile.ObjectMeta, &profile.Spec, true)
		}, derivedOptions("global-security-profiles")...)
	return krt.JoinCollection(
		[]krt.Collection[model.SecurityProfile]{namespacedSecurity, globalSecurity},
		derivedOptions("security-profiles")...)
}

func trafficPolicyModel(metadata metav1.ObjectMeta, spec *agentsv1alpha1.TrafficPolicySpec, global bool) *model.TrafficPolicy {
	namespace := metadata.Namespace
	if global {
		namespace = ""
	}
	return &model.TrafficPolicy{
		Name:         metadata.Name,
		Namespace:    namespace,
		SandboxUID:   metadata.Annotations[agentsv1alpha1.AnnotationSandboxID],
		Global:       global,
		CreationTime: metadata.CreationTimestamp.Time,
		Spec:         *spec.DeepCopy(),
	}
}

func securityProfileModel(metadata metav1.ObjectMeta, spec *agentsv1alpha1.SecurityProfileSpec, global bool) *model.SecurityProfile {
	namespace := metadata.Namespace
	if global {
		namespace = ""
	}
	return &model.SecurityProfile{
		Name:         metadata.Name,
		Namespace:    namespace,
		SandboxUID:   metadata.Annotations[agentsv1alpha1.AnnotationSandboxID],
		Global:       global,
		CreationTime: metadata.CreationTimestamp.Time,
		Spec:         *spec.DeepCopy(),
	}
}
