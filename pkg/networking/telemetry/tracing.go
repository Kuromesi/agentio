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

package telemetry

import (
	"fmt"
	"sort"

	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	uuidv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/request_id/uuid/v3"
	tracingv3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	percentv3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openkruise/agentio/pkg/model"
)

func buildTracing(
	spec tracingSpec,
	provider *model.TelemetryTracingProvider,
	gateway model.Gateway,
	clusterID string,
) (*hcmv3.HttpConnectionManager_Tracing, *hcmv3.RequestIDExtension, error) {
	if spec.Disabled {
		return nil, nil, nil
	}
	sampling := 1.0
	if provider.CustomSampler {
		sampling = 100
	} else if spec.RandomSamplingPercentage != nil {
		sampling = *spec.RandomSamplingPercentage
	}
	result := &hcmv3.HttpConnectionManager_Tracing{
		ClientSampling:  &percentv3.Percent{Value: 100},
		RandomSampling:  &percentv3.Percent{Value: sampling},
		OverallSampling: &percentv3.Percent{Value: 100},
		Provider:        proto.Clone(provider.Provider).(*tracev3.Tracing_Http),
	}
	if provider.SpawnUpstreamSpan {
		result.SpawnUpstreamSpan = wrapperspb.Bool(true)
	}
	if provider.MaxPathTagLength != 0 {
		result.MaxPathTagLength = wrapperspb.UInt32(provider.MaxPathTagLength)
	}
	if spec.EnableIstioTags {
		result.CustomTags = append(result.CustomTags, gatewayIstioTags(gateway, clusterID)...)
	}
	for name, tag := range spec.CustomTags {
		converted, err := convertTracingTag(name, tag)
		if err != nil {
			return nil, nil, err
		}
		result.CustomTags = append(result.CustomTags, converted)
	}
	sort.Slice(result.CustomTags, func(i, j int) bool { return result.CustomTags[i].Tag < result.CustomTags[j].Tag })
	uuidTyped, err := anypb.New(&uuidv3.UuidRequestIdConfig{
		UseRequestIdForTraceSampling: wrapperspb.Bool(spec.UseRequestIDForTraceSampling),
	})
	if err != nil {
		return nil, nil, err
	}
	return result, &hcmv3.RequestIDExtension{TypedConfig: uuidTyped}, nil
}

func convertTracingTag(name string, tag model.TelemetryTracingTag) (*tracingv3.CustomTag, error) {
	result := &tracingv3.CustomTag{Tag: name}
	switch tag.Kind {
	case model.TelemetryTracingTagLiteral:
		result.Type = &tracingv3.CustomTag_Literal_{Literal: &tracingv3.CustomTag_Literal{Value: tag.Value}}
	case model.TelemetryTracingTagEnvironment:
		result.Type = &tracingv3.CustomTag_Environment_{Environment: &tracingv3.CustomTag_Environment{Name: tag.Name, DefaultValue: tag.DefaultValue}}
	case model.TelemetryTracingTagHeader:
		result.Type = &tracingv3.CustomTag_RequestHeader{RequestHeader: &tracingv3.CustomTag_Header{Name: tag.Name, DefaultValue: tag.DefaultValue}}
	case model.TelemetryTracingTagFormatter:
		result.Type = &tracingv3.CustomTag_Value{Value: tag.Value}
	default:
		return nil, fmt.Errorf("tracing tag %q has unsupported kind %d", name, tag.Kind)
	}
	return result, nil
}

func gatewayIstioTags(gateway model.Gateway, clusterID string) []*tracingv3.CustomTag {
	if clusterID == "" {
		clusterID = "unknown"
	}
	literals := map[string]string{
		"istio.canonical_revision": "latest",
		"istio.canonical_service":  gateway.Name,
		"istio.cluster_id":         clusterID,
		"istio.mesh_id":            "unknown",
		"istio.namespace":          gateway.Namespace,
	}
	result := make([]*tracingv3.CustomTag, 0, len(literals)+18)
	for name, value := range literals {
		result = append(result, &tracingv3.CustomTag{Tag: name, Type: &tracingv3.CustomTag_Literal_{Literal: &tracingv3.CustomTag_Literal{Value: value}}})
	}
	for _, peer := range []struct{ prefix, state string }{{"destination", "upstream_peer_obj"}, {"source", "downstream_peer_obj"}} {
		for _, field := range []struct{ tag, field string }{
			{"workload", "workload"}, {"namespace", "namespace"}, {"cluster_id", "cluster"},
			{"canonical_service", "service"}, {"canonical_revision", "revision"}, {"app", "app"},
			{"app_version", "version"}, {"workload_type", "type"}, {"instance_name", "name"},
		} {
			result = append(result, &tracingv3.CustomTag{
				Tag:  "istio." + peer.prefix + "_" + field.tag,
				Type: &tracingv3.CustomTag_Value{Value: fmt.Sprintf("%%FILTER_STATE(%s:FIELD:%s)%%", peer.state, field.field)},
			})
		}
	}
	return result
}
