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
	"sort"

	"istio.io/istio/pkg/util/sets"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// newWorkloadResources owns the incremental joins for WDS networking state
// and gateway dependencies from Workload policy selections. Deterministic protobuf and
// Resource encoding lives in wds.go.
func newWorkloadResources(
	inputs Inputs,
	base baseIndexes,
	metadataConfiguration krt.Singleton[workloadMetadataConfiguration],
	gateways krt.Collection[model.Gateway],
	workloadPolicies krt.Collection[workloadPolicies],
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
			var egressGatewayKeys, trafficPolicyNames, authorizationNames []string
			var egressPolicies *extensionsv1.EgressPolicies
			var sniPolicy *extensionsv1.SniTrafficPolicy
			if selected := krt.FetchOne(ctx, workloadPolicies, krt.FilterKey(workload.UID)); selected != nil {
				trafficPolicyNames = selected.TrafficPolicyNames
				authorizationNames = selected.AuthorizationNames
				sniPolicy = selected.SNIPolicy
				egressPolicies = selected.EgressPolicies
				egressGatewayKeys = selected.GatewayReferences
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
			failures.clearIf("WDSWorkload", workload.UID, currentInput)
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
