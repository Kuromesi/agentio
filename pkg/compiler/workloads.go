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
	"sort"

	"istio.io/istio/pkg/util/sets"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// newWorkloadResources owns the incremental joins for WDS networking state
// and the current Workload-scoped policy overlay. Deterministic protobuf and
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
	return krt.NewManyCollection(inputs.Workloads,
		func(ctx krt.HandlerContext, workload model.Workload) []model.Resource {
			var authorizationNames []string
			var egressPolicies *extensionsv1.EgressPolicies
			var egressGatewayKeys []string
			if len(workload.SandboxBindings) > 0 {
				binding, err := singleSandboxBinding(workload)
				if err != nil {
					failures.record("WDSWorkload", workload.ResourceName(), err)
					return nil
				}
				policyBindings := krt.FetchOne(ctx, policies.sandboxBindings,
					krt.FilterKey(binding.SandboxUID))
				if policyBindings != nil && !policyBindings.Valid() {
					failures.record("WDSWorkload", workload.ResourceName(),
						fmt.Errorf("sandbox %q has invalid policy bindings", binding.SandboxUID))
					return nil
				}
				if policyBindings != nil {
					authorizationNames = policyBindings.PolicyNames(policy.PolicyKindAuthorization)
					egressNames := policyBindings.PolicyNames(policy.PolicyKindEgressPolicy)
					if len(egressNames) > 0 {
						fetched := krt.Fetch(ctx, policies.egressPolicies,
							krt.FilterKeys(egressNames...))
						if len(fetched) != len(egressNames) {
							// Discard the result to keep the previous Workload during the attachment/payload event-ordering window.
							ctx.DiscardResult()
							return nil
						}
						var err error
						egressPolicies, egressGatewayKeys, err = policy.SelectEgressPolicies(
							egressNames,
							fetched,
						)
						if err != nil {
							failures.record("WDSWorkload", workload.ResourceName(), err)
							return nil
						}
					}
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
				AuthorizationNames: authorizationNames,
				Endpoints:          endpoints,
				Services:           services,
				EgressPolicies:     egressPolicies,
				EgressGatewayKeys:  egressGatewayKeys,
				OwnedGatewayKey:    ownedGatewayKey,
			}
			projection.MetadataConfiguration = currentMetadataConfiguration
			resources, err := buildWDSAddress(projection)
			if err != nil {
				failures.record("WDSWorkload", workload.ResourceName(), err)
				return nil
			}
			failures.clear("WDSWorkload", workload.ResourceName())
			return resources
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

func newServiceResources(inputs Inputs, gateways krt.Collection[model.Gateway], failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(inputs.Services, failures, "Service")
	return krt.NewManyCollection(inputs.Services,
		func(ctx krt.HandlerContext, service model.Service) []model.Resource {
			gatewayKey := service.Namespace + "/" + service.Name
			if krt.FetchOne(ctx, gateways, krt.FilterKey(gatewayKey)) == nil {
				gatewayKey = ""
			}
			resource, err := buildWDSService(service, gatewayKey)
			if err != nil {
				failures.record("Service", service.ResourceName(), err)
				return nil
			}
			failures.clear("Service", service.ResourceName())
			return []model.Resource{resource}
		}, options("service-resources")...)
}
