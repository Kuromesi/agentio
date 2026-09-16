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
	"errors"
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// newWorkloadResources owns the incremental joins for WDS networking state
// and gateway dependencies from its own policy bindings. Deterministic protobuf and
// Resource encoding lives in wds.go.
func newWorkloadResources(
	inputs Inputs,
	base baseIndexes,
	metadataConfiguration krt.Singleton[workloadMetadataConfiguration],
	gateways krt.Collection[model.Gateway],
	policies policyCollections,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(inputs.Workloads, failures, "WDSWorkload")
	return krt.NewCollection(inputs.Workloads,
		func(ctx krt.HandlerContext, workload model.Workload) *model.Resource {
			currentInput := func() bool {
				current := inputs.Workloads.GetKey(workload.ResourceName())
				return current != nil && current.Equals(workload)
			}
			var egressGatewayKeys, authorizationNames, trafficPolicyNames []string
			var egressPolicies *extensionsv1.EgressPolicies
			var sniPolicy *extensionsv1.SniTrafficPolicy
			var policyErr error
			if !workload.SandboxManaged {
				refs := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(policy.BindingsKey(policy.PolicyTargetWorkload, workload.UID)))
				if refs != nil {
					authorizationNames = append([]string(nil), refs.PolicyNames(policy.PolicyKindAuthorization)...)
					trafficPolicyNames = append([]string(nil), refs.PolicyNames(policy.PolicyKindTrafficPolicy)...)
					names := refs.PolicyNames(policy.PolicyKindEgressPolicy)
					if len(names) > 0 {
						// FilterKeys sorts its input; binding order is shared and must stay immutable.
						compiled := krt.Fetch(ctx, policies.egressPolicies, krt.FilterKeys(append([]string(nil), names...)...))
						egressPolicies, egressGatewayKeys, policyErr = policy.SelectEgressPolicies(names, compiled)
					}
					var sniErr error
					sniPolicy, sniErr = workloadSNIPolicy(ctx, refs.PolicyNames(model.PolicyKindSNIPolicy), policies.sniPolicies)
					policyErr = errors.Join(policyErr, sniErr)
				}
			}
			ownedGatewayKey := gatewayKeyForWorkload(workload)
			if ownedGatewayKey != "" {
				gateway := krt.FetchOne(ctx, gateways, krt.FilterKey(ownedGatewayKey))
				if gateway == nil || gateway.ValidateForUse() != nil {
					ownedGatewayKey = ""
				}
			}

			endpointsByKey := make(map[string]model.Endpoint)
			if workload.SourceUID != "" {
				for _, endpoint := range krt.Fetch(ctx, inputs.Endpoints,
					krt.FilterIndex(base.endpointsByTargetUID, workload.SourceUID)) {
					endpointsByKey[endpoint.ResourceName()] = endpoint
				}
			}
			for _, endpoint := range krt.Fetch(ctx, inputs.Endpoints,
				krt.FilterIndex(base.endpointsByTargetName, workload.Namespace+"/"+workload.Name)) {
				endpointsByKey[endpoint.ResourceName()] = endpoint
			}
			for _, address := range workload.Addresses {
				for _, endpoint := range krt.Fetch(ctx, inputs.Endpoints,
					krt.FilterIndex(base.endpointsByAddress, address)) {
					endpointsByKey[endpoint.ResourceName()] = endpoint
				}
			}
			endpoints := make([]model.Endpoint, 0, len(endpointsByKey))
			serviceKeys := sets.New[string]()
			readyServiceKeys := sets.New[string]()
			for _, endpoint := range endpointsByKey {
				endpoints = append(endpoints, endpoint)
				serviceKeys.Insert(endpoint.ServiceKey)
				if endpoint.Ready {
					readyServiceKeys.Insert(endpoint.ServiceKey)
				}
			}
			orderedServiceKeys := make([]string, 0, len(serviceKeys))
			for key := range serviceKeys {
				orderedServiceKeys = append(orderedServiceKeys, key)
			}
			sort.Strings(orderedServiceKeys)
			services := make([]model.Service, 0, len(orderedServiceKeys))
			for _, key := range orderedServiceKeys {
				service := krt.FetchOne(ctx, inputs.Services, krt.FilterKey(key))
				if service == nil {
					continue
				}
				if !readyServiceKeys.Contains(key) && !service.PublishNotReadyAddresses {
					continue
				}
				services = append(services, *service)
			}
			currentMetadataConfiguration := krt.FetchOne(ctx, metadataConfiguration.AsCollection())
			projection := wdsProjection{
				ClusterID:          inputs.ClusterID,
				Workload:           workload,
				SNIPolicy:          sniPolicy,
				EgressPolicies:     egressPolicies,
				AuthorizationNames: authorizationNames,
				TrafficPolicyNames: trafficPolicyNames,
				Endpoints:          endpoints,
				Services:           services,
				EgressGatewayKeys:  egressGatewayKeys,
				OwnedGatewayKey:    ownedGatewayKey,
			}
			projection.MetadataConfiguration = currentMetadataConfiguration
			resource, err := buildWDSAddress(projection)
			if err != nil {
				failures.recordIf("WDSWorkload", workload.ResourceName(), err, currentInput)
				return nil
			}
			if policyErr != nil {
				failures.recordIf("WDSWorkload", workload.UID, policyErr, currentInput)
			} else {
				failures.clearIf("WDSWorkload", workload.UID, currentInput)
			}
			return resource
		}, options("workload-resources")...)
}

func gatewayKeyForWorkload(workload model.Workload) string {
	principal := workload.Principal
	if principal.Kind != model.PrincipalServiceAccount ||
		principal.ServiceAccount.Namespace == "" ||
		principal.ServiceAccount.Namespace != workload.Namespace ||
		principal.ServiceAccount.ServiceAccount == "" {
		return ""
	}
	key := principal.ServiceAccount.Namespace + "/" + principal.ServiceAccount.ServiceAccount
	if workload.GatewayKey != "" && workload.GatewayKey != key {
		return ""
	}
	return key
}

// workloadSNIPolicy projects available policies in order, omitting missing bodies.
// Fetches register content dependencies directly on the Workload.
func workloadSNIPolicy(ctx krt.HandlerContext, names []string, sniPolicies krt.Collection[policy.CompiledSNIPolicy]) (*extensionsv1.SniTrafficPolicy, error) {
	if len(names) == 0 {
		return nil, nil
	}
	result := &extensionsv1.SniTrafficPolicy{}
	complete := true
	for _, name := range names {
		compiled := krt.FetchOne(ctx, sniPolicies, krt.FilterKey(name))
		if compiled == nil || compiled.Policy == nil {
			complete = false
			continue
		}
		for _, rule := range compiled.Policy.Rules {
			result.Rules = append(result.Rules, proto.Clone(rule).(*extensionsv1.SniRule))
		}
	}
	if !complete {
		if len(result.Rules) == 0 {
			result = nil
		}
		return result, fmt.Errorf("workload SNI policy content is incomplete: %v", names)
	}
	return result, nil
}
