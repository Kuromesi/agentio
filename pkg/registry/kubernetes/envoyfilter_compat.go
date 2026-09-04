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

// This file is the compatibility boundary for Agentio config-source
// EnvoyFilters. Istio API values must not escape into the internal collection.
package kubernetes

import (
	"fmt"
	"sort"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

const (
	envoyFilterGatewayGroup = "gateway.networking.k8s.io"
	envoyFilterGatewayKind  = "Gateway"

	// Legacy PassthroughCluster route names are translated to http_dynamic_forward_proxy for deployed EnvoyFilters.
	legacyAgentioHTTPPassthroughRouteName = "PassthroughCluster"
	httpDynamicForwardProxyRouteName      = "http_dynamic_forward_proxy"
)

type patchSourceMetadata struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
}

func convertIstioEnvoyFilter(metadata patchSourceMetadata, spec *networking.EnvoyFilter) (*model.GatewayPatch, error) {
	if spec == nil {
		return nil, fmt.Errorf("spec is required")
	}
	targetSet := sets.NewWithLength[string](len(spec.GetTargetRefs()))
	for index, ref := range spec.GetTargetRefs() {
		if ref == nil || ref.GetGroup() != envoyFilterGatewayGroup || ref.GetKind() != envoyFilterGatewayKind {
			continue
		}
		if ref.GetName() == "" {
			return nil, fmt.Errorf("targetRef %d Gateway name is required", index)
		}
		if ref.GetNamespace() != "" && ref.GetNamespace() != metadata.Namespace {
			return nil, fmt.Errorf("targetRef %d crosses namespace from %s to %s", index, metadata.Namespace, ref.GetNamespace())
		}
		targetSet.Insert(metadata.Namespace + "/" + ref.GetName())
	}
	if len(targetSet) == 0 {
		return nil, nil
	}
	targets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	patches := make([]model.EnvoyPatch, 0, len(spec.GetConfigPatches()))
	for index, configPatch := range spec.GetConfigPatches() {
		patch, applicable, err := convertIstioPatch(configPatch)
		if err != nil {
			return nil, fmt.Errorf("configPatch %d: %w", index, err)
		}
		if applicable {
			patches = append(patches, patch)
		}
	}
	if len(patches) == 0 {
		return nil, nil
	}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace:       metadata.Namespace,
		Name:            metadata.Name,
		Source:          metadata.Source,
		ResourceVersion: metadata.ResourceVersion,
		CreationTime:    metadata.CreationTime,
	}, spec.GetPriority(), targets, patches)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func convertIstioPatch(configPatch *networking.EnvoyFilter_EnvoyConfigObjectPatch) (model.EnvoyPatch, bool, error) {
	if configPatch == nil || configPatch.GetPatch() == nil {
		return model.EnvoyPatch{}, false, fmt.Errorf("patch is required")
	}
	match := configPatch.GetMatch()
	if match != nil {
		if proxy := match.GetProxy(); proxy != nil && (proxy.GetProxyVersion() != "" || len(proxy.GetMetadata()) > 0) {
			return model.EnvoyPatch{}, false, fmt.Errorf("runtime proxy match is unsupported")
		}
		switch match.GetContext() {
		case networking.EnvoyFilter_ANY, networking.EnvoyFilter_GATEWAY, networking.EnvoyFilter_SIDECAR_INBOUND:
		case networking.EnvoyFilter_SIDECAR_OUTBOUND:
			return model.EnvoyPatch{}, false, nil
		default:
			return model.EnvoyPatch{}, false, fmt.Errorf("unsupported context %s", match.GetContext())
		}
	}
	if err := validateIstioApplyToMatch(configPatch.GetApplyTo(), match); err != nil {
		return model.EnvoyPatch{}, false, err
	}
	operation, err := normalizeIstioOperation(configPatch.GetApplyTo(), configPatch.GetPatch().GetOperation())
	if err != nil {
		return model.EnvoyPatch{}, false, err
	}
	value, err := decodeIstioPatchValue(configPatch.GetApplyTo(), configPatch.GetPatch().GetValue())
	if err != nil {
		return model.EnvoyPatch{}, false, err
	}
	if value == nil && operation != model.PatchRemove {
		return model.EnvoyPatch{}, false, fmt.Errorf("operation requires a value")
	}

	patch := model.EnvoyPatch{Operation: operation}
	switch configPatch.GetApplyTo() {
	case networking.EnvoyFilter_CLUSTER:
		patch.Target = model.ClusterPatch{Match: convertClusterMatch(match.GetCluster()), Value: castValue[*clusterv3.Cluster](value)}
	case networking.EnvoyFilter_LISTENER:
		patch.Target = model.ListenerPatch{Match: convertListenerMatch(match.GetListener()), Value: castValue[*listenerv3.Listener](value)}
	case networking.EnvoyFilter_LISTENER_FILTER:
		patch.Target = model.ListenerFilterPatch{Match: convertListenerMatch(match.GetListener()), Value: castValue[*listenerv3.ListenerFilter](value)}
	case networking.EnvoyFilter_FILTER_CHAIN:
		patch.Target = model.FilterChainPatch{Match: convertListenerMatch(match.GetListener()), Value: castValue[*listenerv3.FilterChain](value)}
	case networking.EnvoyFilter_NETWORK_FILTER:
		patch.Target = model.NetworkFilterPatch{Match: convertListenerMatch(match.GetListener()), Value: castValue[*listenerv3.Filter](value)}
	case networking.EnvoyFilter_HTTP_FILTER:
		patch.Target = model.HTTPFilterPatch{Match: convertListenerMatch(match.GetListener()), Value: castValue[*hcmv3.HttpFilter](value)}
	case networking.EnvoyFilter_ROUTE_CONFIGURATION:
		patch.Target = model.RouteConfigurationPatch{Match: convertRouteConfigurationMatch(match.GetRouteConfiguration()), Value: castValue[*routev3.RouteConfiguration](value)}
	case networking.EnvoyFilter_VIRTUAL_HOST:
		patch.Target = model.VirtualHostPatch{Match: convertRouteConfigurationMatch(match.GetRouteConfiguration()), Value: castValue[*routev3.VirtualHost](value)}
	case networking.EnvoyFilter_HTTP_ROUTE:
		patch.Target = model.HTTPRoutePatch{Match: convertRouteConfigurationMatch(match.GetRouteConfiguration()), Value: castValue[*routev3.Route](value)}
	case networking.EnvoyFilter_EXTENSION_CONFIG:
		patch.Target = model.ExtensionConfigurationPatch{Value: castValue[*corev3.TypedExtensionConfig](value)}
	default:
		return model.EnvoyPatch{}, false, fmt.Errorf("unsupported applyTo %s", configPatch.GetApplyTo())
	}
	return patch, true, nil
}

func validateIstioApplyToMatch(applyTo networking.EnvoyFilter_ApplyTo, match *networking.EnvoyFilter_EnvoyConfigObjectMatch) error {
	if match == nil || match.ObjectTypes == nil {
		return nil
	}
	var valid bool
	switch applyTo {
	case networking.EnvoyFilter_CLUSTER:
		valid = match.GetCluster() != nil
	case networking.EnvoyFilter_LISTENER, networking.EnvoyFilter_LISTENER_FILTER, networking.EnvoyFilter_FILTER_CHAIN,
		networking.EnvoyFilter_NETWORK_FILTER, networking.EnvoyFilter_HTTP_FILTER:
		valid = match.GetListener() != nil
	case networking.EnvoyFilter_ROUTE_CONFIGURATION, networking.EnvoyFilter_VIRTUAL_HOST, networking.EnvoyFilter_HTTP_ROUTE:
		valid = match.GetRouteConfiguration() != nil
	case networking.EnvoyFilter_EXTENSION_CONFIG:
		// ECDS patches have no object-match family. Accepting a cluster,
		// listener, or route match here would discard it during conversion and
		// widen the patch into an unconditional extension ADD.
		valid = false
	default:
		return nil
	}
	if !valid {
		return fmt.Errorf("applyTo %s cannot use %T match", applyTo, match.ObjectTypes)
	}
	return nil
}

func normalizeIstioOperation(applyTo networking.EnvoyFilter_ApplyTo, operation networking.EnvoyFilter_Patch_Operation) (model.PatchOperation, error) {
	insert := operation == networking.EnvoyFilter_Patch_INSERT_BEFORE || operation == networking.EnvoyFilter_Patch_INSERT_AFTER ||
		operation == networking.EnvoyFilter_Patch_INSERT_FIRST
	if insert {
		switch applyTo {
		case networking.EnvoyFilter_LISTENER_FILTER, networking.EnvoyFilter_NETWORK_FILTER,
			networking.EnvoyFilter_HTTP_FILTER, networking.EnvoyFilter_HTTP_ROUTE:
		default:
			operation = networking.EnvoyFilter_Patch_ADD
		}
	}
	converted := map[networking.EnvoyFilter_Patch_Operation]model.PatchOperation{
		networking.EnvoyFilter_Patch_ADD:           model.PatchAdd,
		networking.EnvoyFilter_Patch_MERGE:         model.PatchMerge,
		networking.EnvoyFilter_Patch_REMOVE:        model.PatchRemove,
		networking.EnvoyFilter_Patch_REPLACE:       model.PatchReplace,
		networking.EnvoyFilter_Patch_INSERT_BEFORE: model.PatchInsertBefore,
		networking.EnvoyFilter_Patch_INSERT_AFTER:  model.PatchInsertAfter,
		networking.EnvoyFilter_Patch_INSERT_FIRST:  model.PatchInsertFirst,
	}[operation]
	if converted == 0 || !operationSupported(applyTo, converted) {
		return 0, fmt.Errorf("operation %s is unsupported for applyTo %s", operation, applyTo)
	}
	return converted, nil
}

func operationSupported(applyTo networking.EnvoyFilter_ApplyTo, operation model.PatchOperation) bool {
	switch applyTo {
	case networking.EnvoyFilter_CLUSTER, networking.EnvoyFilter_LISTENER, networking.EnvoyFilter_FILTER_CHAIN:
		return operation == model.PatchAdd || operation == model.PatchMerge || operation == model.PatchRemove
	case networking.EnvoyFilter_LISTENER_FILTER, networking.EnvoyFilter_NETWORK_FILTER, networking.EnvoyFilter_HTTP_FILTER:
		return operation >= model.PatchAdd && operation <= model.PatchInsertFirst
	case networking.EnvoyFilter_ROUTE_CONFIGURATION:
		return operation == model.PatchMerge
	case networking.EnvoyFilter_VIRTUAL_HOST:
		return operation == model.PatchAdd || operation == model.PatchMerge || operation == model.PatchRemove || operation == model.PatchReplace
	case networking.EnvoyFilter_HTTP_ROUTE:
		return operation == model.PatchAdd || operation == model.PatchMerge || operation == model.PatchRemove ||
			operation == model.PatchInsertBefore || operation == model.PatchInsertAfter || operation == model.PatchInsertFirst
	case networking.EnvoyFilter_EXTENSION_CONFIG:
		return operation == model.PatchAdd
	default:
		return false
	}
}

func decodeIstioPatchValue(applyTo networking.EnvoyFilter_ApplyTo, value *structpb.Struct) (proto.Message, error) {
	if value == nil {
		return nil, nil
	}
	var object proto.Message
	switch applyTo {
	case networking.EnvoyFilter_CLUSTER:
		object = &clusterv3.Cluster{}
	case networking.EnvoyFilter_LISTENER:
		object = &listenerv3.Listener{}
	case networking.EnvoyFilter_LISTENER_FILTER:
		object = &listenerv3.ListenerFilter{}
	case networking.EnvoyFilter_FILTER_CHAIN:
		object = &listenerv3.FilterChain{}
	case networking.EnvoyFilter_NETWORK_FILTER:
		object = &listenerv3.Filter{}
	case networking.EnvoyFilter_HTTP_FILTER:
		object = &hcmv3.HttpFilter{}
	case networking.EnvoyFilter_ROUTE_CONFIGURATION:
		object = &routev3.RouteConfiguration{}
	case networking.EnvoyFilter_VIRTUAL_HOST:
		object = &routev3.VirtualHost{}
	case networking.EnvoyFilter_HTTP_ROUTE:
		object = &routev3.Route{}
	case networking.EnvoyFilter_EXTENSION_CONFIG:
		object = &corev3.TypedExtensionConfig{}
	default:
		return nil, fmt.Errorf("unsupported applyTo %s", applyTo)
	}
	encoded, err := protojson.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal patch value: %w", err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(encoded, object); err != nil {
		return nil, fmt.Errorf("decode %s patch value: %w", applyTo, err)
	}
	return object, nil
}

func castValue[T proto.Message](value proto.Message) T {
	if value == nil {
		var zero T
		return zero
	}
	return value.(T)
}

func convertClusterMatch(match *networking.EnvoyFilter_ClusterMatch) *model.ClusterMatch {
	if match == nil {
		return nil
	}
	return &model.ClusterMatch{Name: match.GetName(), Service: match.GetService(), Subset: match.GetSubset(), PortNumber: match.GetPortNumber()}
}

func convertListenerMatch(match *networking.EnvoyFilter_ListenerMatch) *model.ListenerMatch {
	if match == nil {
		return nil
	}
	result := &model.ListenerMatch{Name: match.GetName(), PortNumber: match.GetPortNumber(), ListenerFilter: match.GetListenerFilter()}
	if chain := match.GetFilterChain(); chain != nil {
		result.FilterChain = &model.FilterChainMatch{
			Name: chain.GetName(), SNI: chain.GetSni(), TransportProtocol: chain.GetTransportProtocol(),
			ApplicationProtocols: chain.GetApplicationProtocols(), DestinationPort: chain.GetDestinationPort(),
		}
		if filter := chain.GetFilter(); filter != nil {
			result.FilterChain.Filter = &model.FilterMatch{Name: filter.GetName()}
			if subFilter := filter.GetSubFilter(); subFilter != nil {
				result.FilterChain.Filter.SubFilter = &model.SubFilterMatch{Name: subFilter.GetName()}
			}
		}
	}
	return result
}

func convertRouteConfigurationMatch(match *networking.EnvoyFilter_RouteConfigurationMatch) *model.RouteConfigurationMatch {
	if match == nil {
		return nil
	}
	result := &model.RouteConfigurationMatch{
		Name:     normalizeAgentioRouteConfigurationName(match.GetName()),
		PortName: match.GetPortName(), Gateway: match.GetGateway(), PortNumber: match.GetPortNumber(),
	}
	if host := match.GetVhost(); host != nil {
		result.VirtualHost = &model.VirtualHostMatch{Name: host.GetName(), DomainName: host.GetDomainName()}
		if route := host.GetRoute(); route != nil {
			result.VirtualHost.Route = &model.RouteMatch{Name: route.GetName(), Action: convertRouteAction(route.GetAction())}
		}
	}
	return result
}

func normalizeAgentioRouteConfigurationName(name string) string {
	if name == legacyAgentioHTTPPassthroughRouteName {
		return httpDynamicForwardProxyRouteName
	}
	return name
}

func convertRouteAction(action networking.EnvoyFilter_RouteConfigurationMatch_RouteMatch_Action) model.RouteAction {
	switch action {
	case networking.EnvoyFilter_RouteConfigurationMatch_RouteMatch_ROUTE:
		return model.RouteActionRoute
	case networking.EnvoyFilter_RouteConfigurationMatch_RouteMatch_REDIRECT:
		return model.RouteActionRedirect
	case networking.EnvoyFilter_RouteConfigurationMatch_RouteMatch_DIRECT_RESPONSE:
		return model.RouteActionDirectResponse
	default:
		return model.RouteActionAny
	}
}
