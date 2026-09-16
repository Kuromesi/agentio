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

package compiler

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

type policyCollections struct {
	trafficPolicies krt.Collection[policy.CompiledTrafficPolicy]
	sniPolicies     krt.Collection[policy.CompiledSNIPolicy]
	egressPolicies  krt.Collection[policy.CompiledEgressPolicy]

	// Shared binding metadata for all policy families, without rule bodies.
	policyBindings krt.Collection[policy.Bindings]
}

// newTrafficPolicyInputs shares peer-resolution indexes across Sandbox and shared-policy compilation.
func newTrafficPolicyInputs(inputs Inputs) policy.TrafficPolicyInputs {
	podsByNamespace := krt.NewIndex(inputs.Pods, "trafficPolicyPodsByNamespace",
		func(pod *corev1.Pod) []string { return []string{pod.Namespace} })
	kubernetesServicesByNamespace := krt.NewIndex(inputs.KubernetesServices, "trafficPolicyKubernetesServicesByNamespace",
		func(service *corev1.Service) []string { return []string{service.Namespace} })
	endpointSlicesByService := krt.NewIndex(inputs.EndpointSlices, "trafficPolicyEndpointSlicesByService",
		func(slice *discoveryv1.EndpointSlice) []string {
			serviceName, found := slice.Labels[discoveryv1.LabelServiceName]
			if !found {
				return nil
			}
			return []string{slice.Namespace + "/" + serviceName}
		})
	return policy.TrafficPolicyInputs{
		RootNamespace:           inputs.RootNamespace,
		Services:                inputs.KubernetesServices,
		EndpointSlices:          inputs.EndpointSlices,
		Pods:                    inputs.Pods,
		ServicesByNamespace:     kubernetesServicesByNamespace,
		EndpointSlicesByService: endpointSlicesByService,
		PodsByNamespace:         podsByNamespace,
		Resolve:                 inputs.Resolve,
	}
}

// newPolicyCollections builds the compiled-policy stages and the attachment
// indexes over them. The graph retains the result because both the workload
// family and the policy resource families consume it after construction.
func newPolicyCollections(
	inputs Inputs,
	configurations krt.Singleton[configuration],
	trafficPolicyInputs policy.TrafficPolicyInputs,
	failures *failureRecorder,
	options collectionOptions,
	builder krt.OptionsBuilder,
) policyCollections {
	clearFailureOnSourceDelete(inputs.TrafficPolicies, failures, "TrafficPolicy")
	clearFailureOnSourceDelete(inputs.SecurityProfiles, failures, "SecurityProfile")

	trafficPolicies := krt.NewCollection(inputs.TrafficPolicies,
		func(ctx krt.HandlerContext, source model.TrafficPolicy) *policy.CompiledTrafficPolicy {
			compiled, err := policy.CompileTrafficPolicy(ctx, source, trafficPolicyInputs)
			if err != nil {
				failures.record("TrafficPolicy", source.ResourceName(), err)
				if !source.Dedicated {
					ctx.DiscardResult()
				}
				return nil
			}
			failures.clear("TrafficPolicy", source.ResourceName())
			return compiled
		}, options("traffic-policies")...)

	sniPolicies := krt.NewCollection(inputs.SecurityProfiles,
		func(ctx krt.HandlerContext, profile model.SecurityProfile) *policy.CompiledSNIPolicy {
			compiled, err := policy.CompileSNIProfile(profile)
			if err != nil {
				failures.record("SecurityProfile", profile.ResourceName(), err)
				if !profile.Dedicated {
					ctx.DiscardResult()
				}
				return nil
			}
			failures.clear("SecurityProfile", profile.ResourceName())
			return compiled
		}, options("sni-policies")...)
	egressPolicies := krt.NewManyCollection(configurations.AsCollection(),
		func(ctx krt.HandlerContext, current configuration) []policy.CompiledEgressPolicy {
			compiled, err := policy.CompiledEgressPolicies(inputs.RootNamespace, current.Egress)
			if err != nil {
				failures.record("AgentioConfig", "configuration", err)
				ctx.DiscardResult()
				return nil
			}
			failures.clear("AgentioConfig", "configuration")
			return compiled
		}, options("bindable-egress-policies")...)
	// Project only metadata, so rule-body updates do not invalidate bindings.
	trafficAttachments := policy.NewPolicyAttachmentsCollection(trafficPolicies, builder, "traffic-policy-attachments")
	sniAttachments := policy.NewPolicyAttachmentsCollection(sniPolicies, builder, "sni-policy-attachments")
	egressAttachments := policy.NewPolicyAttachmentsCollection(egressPolicies, builder, "egress-policy-attachments")
	attachments := krt.JoinCollection([]krt.Collection[policy.PolicyAttachment]{
		trafficAttachments, sniAttachments, egressAttachments,
	}, options("policy-attachments")...)
	policyBindings := policy.NewPolicyBindingsCollection(inputs.Sandboxes, attachments, builder)
	policyBindings = krt.NewCollection(policyBindings,
		func(_ krt.HandlerContext, binding policy.Bindings) *policy.Bindings {
			if !binding.Valid() {
				reason := binding.InvalidReason
				if reason == "" {
					reason = fmt.Sprintf("unresolved policy references: %v", binding.Unresolved)
				}
				failures.record("Bindings", binding.ResourceName(),
					fmt.Errorf("invalid policy bindings: %s", reason))
			} else {
				failures.clear("Bindings", binding.ResourceName())
			}
			return &binding
		}, options("validated-policy-bindings")...)
	clearFailureOnSourceDelete(policyBindings, failures, "Bindings")
	return policyCollections{
		trafficPolicies: trafficPolicies,
		sniPolicies:     sniPolicies,
		egressPolicies:  egressPolicies,
		policyBindings:  policyBindings,
	}
}

func authorizationResource(authorization policy.CompiledAuthorization) (model.Resource, error) {
	// The Any is built with the istio.security type URL because the local descriptor uses agentio.security.
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(authorization.Policy)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal Authorization %s: %w", authorization.ResourceName(), err)
	}
	value := &anypb.Any{
		TypeUrl: model.WorkloadAuthorizationType,
		Value:   data,
	}
	facts := model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{}}
	switch authorization.Policy.GetScope() {
	case securityv1.Scope_GLOBAL:
		facts.Authorization.Scope = model.AuthorizationScopeGlobal
	case securityv1.Scope_NAMESPACE:
		facts.Authorization.Scope = model.AuthorizationScopeNamespace
		facts.Authorization.Namespace = authorization.Policy.GetNamespace()
	case securityv1.Scope_WORKLOAD_SELECTOR:
		facts.Authorization.Scope = model.AuthorizationScopeWorkload
	}
	return model.NewResource(
		model.ResourceKey{
			TypeURL: model.WorkloadAuthorizationType,
			Name:    authorization.ResourceName(),
		}, "", value, nil, facts)
}

// Shared policy bodies are serialized independently of Sandbox references.
// Legacy Authorizations are emitted only by the Sandbox compatibility branch.
func newTrafficPolicyResources(policies krt.Collection[policy.CompiledTrafficPolicy], failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(policies, failures, "TrafficPolicyResource")
	return krt.NewManyCollection(policies, func(_ krt.HandlerContext, compiled policy.CompiledTrafficPolicy) []model.Resource {
		resources, err := trafficPolicyResources(compiled)
		if err != nil {
			failures.record("TrafficPolicyResource", compiled.Name, err)
			return nil
		}
		failures.clear("TrafficPolicyResource", compiled.Name)
		return resources
	}, options("traffic-policy-resources")...)
}

func trafficPolicyResources(compiled policy.CompiledTrafficPolicy) ([]model.Resource, error) {
	if compiled.Attachment == nil {
		// Sandbox-owned policies are emitted only inside their owner's resource.
		return nil, nil
	}
	value, err := marshalDeterministicAny(compiled.Policy)
	if err != nil {
		return nil, err
	}
	resource, err := model.NewResource(model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: compiled.Name}, "", value, nil, model.ResourceFacts{})
	if err != nil {
		return nil, err
	}
	return []model.Resource{resource}, nil
}
