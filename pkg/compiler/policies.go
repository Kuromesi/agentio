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

// newPolicyCollections builds the compiled-policy stages and the attachment
// indexes over them. The graph retains the result because both the workload
// family and the policy resource families consume it after construction.
func newPolicyCollections(
	inputs Inputs,
	configurations krt.Singleton[configuration],
	failures *failureRecorder,
	options collectionOptions,
	builder krt.OptionsBuilder,
) policyCollections {
	subjects := krt.NewManyCollection(inputs.Workloads,
		func(ctx krt.HandlerContext, workload model.Workload) []policy.SandboxSubject {
			result := make([]policy.SandboxSubject, 0, len(workload.SandboxBindings))
			for _, binding := range workload.SandboxBindings {
				sandbox := krt.FetchOne(ctx, inputs.Sandboxes, krt.FilterKey(binding.SandboxUID))
				result = append(result, sandboxSubject(workload, binding, sandbox))
			}
			return result
		}, options("sandbox-policy-subjects")...)
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
	trafficPolicyInputs := policy.TrafficPolicyInputs{
		RootNamespace:           inputs.RootNamespace,
		Services:                inputs.KubernetesServices,
		EndpointSlices:          inputs.EndpointSlices,
		Pods:                    inputs.Pods,
		ServicesByNamespace:     kubernetesServicesByNamespace,
		EndpointSlicesByService: endpointSlicesByService,
		PodsByNamespace:         podsByNamespace,
		Resolve:                 inputs.Resolve,
	}
	clearFailureOnSourceDelete(inputs.TrafficPolicies, failures, "TrafficPolicy")
	clearFailureOnSourceDelete(inputs.SecurityProfiles, failures, "SecurityProfile")

	authorizations := krt.NewManyCollection(inputs.TrafficPolicies,
		func(ctx krt.HandlerContext, source model.TrafficPolicy) []policy.CompiledAuthorization {
			compiled, err := policy.CompileTrafficPolicy(ctx, source, trafficPolicyInputs)
			if err != nil {
				failures.record("TrafficPolicy", source.ResourceName(), err)
				ctx.DiscardResult()
				return nil
			}
			failures.clear("TrafficPolicy", source.ResourceName())
			return compiled
		}, options("authorizations")...)

	bindableSNIPolicies := krt.NewCollection(inputs.SecurityProfiles,
		func(ctx krt.HandlerContext, profile model.SecurityProfile) *policy.BindableSNIPolicy {
			compiled, err := policy.CompileSNIProfile(profile)
			if err != nil {
				failures.record("SecurityProfile", profile.ResourceName(), err)
				ctx.DiscardResult()
				return nil
			}
			failures.clear("SecurityProfile", profile.ResourceName())
			return compiled
		}, options("sni-policies")...)
	egressPolicies := krt.NewManyCollection(configurations.AsCollection(),
		func(ctx krt.HandlerContext, current configuration) []policy.BindableEgressPolicy {
			compiled, err := policy.BindableEgressPolicies(inputs.RootNamespace, current.Egress)
			if err != nil {
				failures.record("AgentioConfig", "configuration", err)
				ctx.DiscardResult()
				return nil
			}
			failures.clear("AgentioConfig", "configuration")
			return compiled
		}, options("bindable-egress-policies")...)
	authorizationAttachments := policy.NewAuthorizationPolicyAttachmentsCollection(authorizations, builder)
	sniAttachments := policy.NewSNIPolicyAttachmentsCollection(bindableSNIPolicies, builder)
	egressAttachments := policy.NewEgressPolicyAttachmentsCollection(egressPolicies, builder)
	attachments := krt.JoinCollection([]krt.Collection[policy.PolicyAttachment]{
		authorizationAttachments, sniAttachments, egressAttachments,
	}, options("policy-attachments")...)
	sandboxBindings := policy.NewSandboxPolicyBindingsCollection(inputs.Sandboxes, subjects, attachments, builder)
	sandboxBindings = krt.NewCollection(sandboxBindings,
		func(_ krt.HandlerContext, binding policy.SandboxPolicyBindings) *policy.SandboxPolicyBindings {
			if !binding.Valid() {
				reason := binding.InvalidReason
				if reason == "" {
					reason = fmt.Sprintf("unresolved policy references: %v", binding.Unresolved)
				}
				failures.record("Sandbox", binding.SandboxUID,
					fmt.Errorf("invalid policy bindings: %s", reason))
			} else {
				failures.clear("Sandbox", binding.SandboxUID)
			}
			return &binding
		}, options("validated-sandbox-policy-bindings")...)
	clearFailureOnSourceDelete(sandboxBindings, failures, "Sandbox")
	return policyCollections{
		authorizations:      authorizations,
		bindableSNIPolicies: bindableSNIPolicies,
		egressPolicies:      egressPolicies,
		sandboxBindings:     sandboxBindings,
	}
}

func sandboxSubject(workload model.Workload, binding model.SandboxBinding, sandbox *model.Sandbox) policy.SandboxSubject {
	subject := policy.SandboxSubject{
		SandboxUID: binding.SandboxUID,
		Namespace:  workload.Namespace,
		Labels:     workload.Labels,
		Addresses:  workload.Addresses,
		Ready:      workload.Ready,
	}
	// A concrete Sandbox owns its selector metadata, including an intentionally
	// empty namespace or label set. Workload metadata is only the compatibility
	// projection for an implicit Pod-shaped Sandbox with no domain value.
	if sandbox != nil {
		subject.Namespace = sandbox.Namespace
		subject.Labels = sandbox.Labels
	}
	return subject
}

func newAuthorizationResources(policies policyCollections, failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(policies.authorizations, failures, "Authorization")
	return krt.NewCollection(policies.authorizations,
		func(_ krt.HandlerContext, authorization policy.CompiledAuthorization) *model.Resource {
			resource, err := authorizationResource(authorization)
			if err != nil {
				failures.record("Authorization", authorization.ResourceName(), err)
				return nil
			}
			failures.clear("Authorization", authorization.ResourceName())
			return &resource
		}, options("authorization-resources")...)
}

func newSNIResources(policies policyCollections, failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(policies.bindableSNIPolicies, failures, "SniTrafficPolicy")
	return krt.NewCollection(policies.bindableSNIPolicies,
		func(_ krt.HandlerContext, compiled policy.BindableSNIPolicy) *model.Resource {
			resource, err := sniResource(compiled)
			if err != nil {
				failures.record("SniTrafficPolicy", compiled.ResourceName(), err)
				return nil
			}
			failures.clear("SniTrafficPolicy", compiled.ResourceName())
			return &resource
		}, options("sni-resources")...)
}

func authorizationResource(authorization policy.CompiledAuthorization) (model.Resource, error) {
	// The Any is built with the istio.security type URL because the local descriptor uses agentio.security.
	data, err := proto.Marshal(authorization.Authorization)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal Authorization %s: %w", authorization.ResourceName(), err)
	}
	value := &anypb.Any{
		TypeUrl: model.WorkloadAuthorizationType,
		Value:   data,
	}
	facts := model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{}}
	switch authorization.Authorization.GetScope() {
	case securityv1.Scope_GLOBAL:
		facts.Authorization.Scope = model.AuthorizationScopeGlobal
	case securityv1.Scope_NAMESPACE:
		facts.Authorization.Scope = model.AuthorizationScopeNamespace
		facts.Authorization.Namespace = authorization.Authorization.GetNamespace()
	case securityv1.Scope_WORKLOAD_SELECTOR:
		facts.Authorization.Scope = model.AuthorizationScopeWorkload
	}
	return model.NewResource(
		model.ResourceKey{
			TypeURL: model.WorkloadAuthorizationType,
			Name:    authorization.ResourceName(),
		}, "", value, nil, facts)
}

func sniResource(compiled policy.BindableSNIPolicy) (model.Resource, error) {
	value, err := anypb.New(compiled.Policy)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal SNI policy %s: %w", compiled.ResourceName(), err)
	}
	return model.NewResource(
		model.ResourceKey{
			TypeURL: model.SniTrafficPolicyType,
			Name:    compiled.ResourceName(),
		}, "", value, nil, model.ResourceFacts{})
}
