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
// Telemetry. Istio API values must not escape into the internal collection.
package kubernetes

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/types/known/wrapperspb"
	telemetryapi "istio.io/api/telemetry/v1alpha1"
	typeapi "istio.io/api/type/v1beta1"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

type telemetrySourceMetadata struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
}

func convertIstioTelemetry(metadata telemetrySourceMetadata, spec *telemetryapi.Telemetry) (model.Telemetry, error) {
	if spec == nil {
		return model.Telemetry{}, fmt.Errorf("spec is required")
	}
	if spec.Selector != nil {
		return model.Telemetry{}, fmt.Errorf("selector is unsupported for egress Gateway Telemetry")
	}
	if spec.TargetRef != nil && len(spec.TargetRefs) > 0 {
		return model.Telemetry{}, fmt.Errorf("targetRef and targetRefs cannot both be set")
	}
	references := spec.TargetRefs
	if spec.TargetRef != nil {
		references = []*typeapi.PolicyTargetReference{spec.TargetRef}
	}
	targets, err := convertTelemetryTargets(metadata.Namespace, references)
	if err != nil {
		return model.Telemetry{}, err
	}
	metrics, err := convertTelemetryMetrics(spec.Metrics)
	if err != nil {
		return model.Telemetry{}, err
	}
	tracing, err := convertTelemetryTracing(spec.Tracing)
	if err != nil {
		return model.Telemetry{}, err
	}
	logging, err := convertTelemetryAccessLogging(spec.AccessLogging)
	if err != nil {
		return model.Telemetry{}, err
	}
	return model.NewTelemetry(model.TelemetryMetadata{
		Namespace:       metadata.Namespace,
		Name:            metadata.Name,
		Source:          metadata.Source,
		ResourceVersion: metadata.ResourceVersion,
		CreationTime:    metadata.CreationTime,
	}, targets, metrics, tracing, logging)
}

func convertTelemetryTargets(namespace string, references []*typeapi.PolicyTargetReference) ([]string, error) {
	targets := make([]string, 0, len(references))
	seen := sets.NewWithLength[string](len(references))
	for index, reference := range references {
		if reference == nil {
			return nil, fmt.Errorf("targetRef %d is required", index)
		}
		if reference.GetGroup() != envoyFilterGatewayGroup || reference.GetKind() != envoyFilterGatewayKind {
			return nil, fmt.Errorf("unsupported targetRef %d %s/%s", index, reference.GetGroup(), reference.GetKind())
		}
		if reference.GetName() == "" {
			return nil, fmt.Errorf("targetRef %d Gateway name is required", index)
		}
		if reference.GetNamespace() != "" && reference.GetNamespace() != namespace {
			return nil, fmt.Errorf("targetRef %d crosses namespace from %s to %s", index, namespace, reference.GetNamespace())
		}
		target := namespace + "/" + reference.GetName()
		if seen.Contains(target) {
			return nil, fmt.Errorf("targetRef %d duplicates Gateway %s", index, target)
		}
		seen.Insert(target)
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets, nil
}

func convertTelemetryMetrics(input []*telemetryapi.Metrics) ([]model.TelemetryMetrics, error) {
	result := make([]model.TelemetryMetrics, 0, len(input))
	for index, metrics := range input {
		if metrics == nil {
			return nil, fmt.Errorf("metrics %d is required", index)
		}
		converted := model.TelemetryMetrics{Providers: convertTelemetryProviderRefs(metrics.GetProviders())}
		if interval := metrics.GetReportingInterval(); interval != nil {
			if err := interval.CheckValid(); err != nil {
				return nil, fmt.Errorf("metrics %d reporting interval: %w", index, err)
			}
			value := interval.AsDuration()
			converted.ReportingInterval = &value
		}
		for overrideIndex, override := range metrics.GetOverrides() {
			if override == nil {
				return nil, fmt.Errorf("metrics %d override %d is required", index, overrideIndex)
			}
			match, err := convertTelemetryMetricSelector(override.GetMatch())
			if err != nil {
				return nil, fmt.Errorf("metrics %d override %d: %w", index, overrideIndex, err)
			}
			item := model.TelemetryMetricOverride{Match: match, Disabled: wrapperBool(override.Disabled)}
			if override.TagOverrides != nil {
				item.TagOverrides = make(map[string]model.TelemetryMetricTagOverride, len(override.TagOverrides))
			}
			for name, tag := range override.TagOverrides {
				if tag == nil {
					return nil, fmt.Errorf("metrics %d override %d tag %q is required", index, overrideIndex, name)
				}
				switch tag.GetOperation() {
				case telemetryapi.MetricsOverrides_TagOverride_REMOVE:
					item.TagOverrides[name] = model.TelemetryMetricTagOverride{Operation: model.TelemetryTagRemove}
				case telemetryapi.MetricsOverrides_TagOverride_UPSERT:
					item.TagOverrides[name] = model.TelemetryMetricTagOverride{Operation: model.TelemetryTagUpsert, Value: tag.GetValue()}
				default:
					return nil, fmt.Errorf("metrics %d override %d tag %q has unsupported operation %s",
						index, overrideIndex, name, tag.GetOperation())
				}
			}
			converted.Overrides = append(converted.Overrides, item)
		}
		result = append(result, converted)
	}
	return result, nil
}

func convertTelemetryMetricSelector(selector *telemetryapi.MetricSelector) (model.TelemetryMetricSelector, error) {
	result := model.TelemetryMetricSelector{Kind: model.TelemetryMetricAll, Mode: model.TelemetryModeClientAndServer}
	if selector == nil {
		return result, nil
	}
	mode, err := convertTelemetryMode(selector.GetMode())
	if err != nil {
		return model.TelemetryMetricSelector{}, err
	}
	result.Mode = mode
	switch match := selector.GetMetricMatch().(type) {
	case nil:
	case *telemetryapi.MetricSelector_Metric:
		if match.Metric == telemetryapi.MetricSelector_ALL_METRICS {
			break
		}
		name, found := telemetryapi.MetricSelector_IstioMetric_name[int32(match.Metric)]
		if !found {
			return model.TelemetryMetricSelector{}, fmt.Errorf("unknown standard metric %d", match.Metric)
		}
		result.Kind = model.TelemetryMetricStandard
		result.Name = name
	case *telemetryapi.MetricSelector_CustomMetric:
		result.Kind = model.TelemetryMetricCustom
		result.Name = match.CustomMetric
	default:
		return model.TelemetryMetricSelector{}, fmt.Errorf("unsupported metric selector %T", match)
	}
	return result, nil
}

func convertTelemetryTracing(input []*telemetryapi.Tracing) ([]model.TelemetryTracing, error) {
	result := make([]model.TelemetryTracing, 0, len(input))
	for index, tracing := range input {
		if tracing == nil {
			return nil, fmt.Errorf("tracing %d is required", index)
		}
		mode := telemetryapi.WorkloadMode_CLIENT_AND_SERVER
		if tracing.Match != nil {
			mode = tracing.Match.GetMode()
		}
		convertedMode, err := convertTelemetryMode(mode)
		if err != nil {
			return nil, fmt.Errorf("tracing %d: %w", index, err)
		}
		converted := model.TelemetryTracing{
			Mode:                         convertedMode,
			Providers:                    convertTelemetryProviderRefs(tracing.GetProviders()),
			RandomSamplingPercentage:     wrapperDouble(tracing.RandomSamplingPercentage),
			DisableSpanReporting:         wrapperBool(tracing.DisableSpanReporting),
			UseRequestIDForTraceSampling: wrapperBool(tracing.UseRequestIdForTraceSampling),
			EnableIstioTags:              wrapperBool(tracing.EnableIstioTags),
		}
		if tracing.CustomTags != nil {
			converted.CustomTags = make(map[string]model.TelemetryTracingTag, len(tracing.CustomTags))
		}
		for name, tag := range tracing.CustomTags {
			convertedTag, err := convertTelemetryTracingTag(tag)
			if err != nil {
				return nil, fmt.Errorf("tracing %d custom tag %q: %w", index, name, err)
			}
			converted.CustomTags[name] = convertedTag
		}
		result = append(result, converted)
	}
	return result, nil
}

func convertTelemetryTracingTag(tag *telemetryapi.Tracing_CustomTag) (model.TelemetryTracingTag, error) {
	if tag == nil {
		return model.TelemetryTracingTag{}, fmt.Errorf("tag is required")
	}
	switch value := tag.Type.(type) {
	case *telemetryapi.Tracing_CustomTag_Literal:
		if value.Literal == nil {
			return model.TelemetryTracingTag{}, fmt.Errorf("literal is required")
		}
		return model.TelemetryTracingTag{Kind: model.TelemetryTracingTagLiteral, Value: value.Literal.GetValue()}, nil
	case *telemetryapi.Tracing_CustomTag_Environment:
		if value.Environment == nil {
			return model.TelemetryTracingTag{}, fmt.Errorf("environment is required")
		}
		return model.TelemetryTracingTag{Kind: model.TelemetryTracingTagEnvironment,
			Name: value.Environment.GetName(), DefaultValue: value.Environment.GetDefaultValue()}, nil
	case *telemetryapi.Tracing_CustomTag_Header:
		if value.Header == nil {
			return model.TelemetryTracingTag{}, fmt.Errorf("header is required")
		}
		return model.TelemetryTracingTag{Kind: model.TelemetryTracingTagHeader,
			Name: value.Header.GetName(), DefaultValue: value.Header.GetDefaultValue()}, nil
	case *telemetryapi.Tracing_CustomTag_Formatter:
		if value.Formatter == nil {
			return model.TelemetryTracingTag{}, fmt.Errorf("formatter is required")
		}
		return model.TelemetryTracingTag{Kind: model.TelemetryTracingTagFormatter, Value: value.Formatter.GetValue()}, nil
	default:
		return model.TelemetryTracingTag{}, fmt.Errorf("tag type is required")
	}
}

func convertTelemetryAccessLogging(input []*telemetryapi.AccessLogging) ([]model.TelemetryAccessLogging, error) {
	result := make([]model.TelemetryAccessLogging, 0, len(input))
	for index, logging := range input {
		if logging == nil {
			return nil, fmt.Errorf("access logging %d is required", index)
		}
		mode := telemetryapi.WorkloadMode_CLIENT_AND_SERVER
		if logging.Match != nil {
			mode = logging.Match.GetMode()
		}
		convertedMode, err := convertTelemetryMode(mode)
		if err != nil {
			return nil, fmt.Errorf("access logging %d: %w", index, err)
		}
		converted := model.TelemetryAccessLogging{
			Mode:      convertedMode,
			Providers: convertTelemetryProviderRefs(logging.GetProviders()),
			Disabled:  wrapperBool(logging.Disabled),
		}
		if logging.Filter != nil {
			expression := logging.Filter.GetExpression()
			environment, err := cel.NewEnv()
			if err != nil {
				return nil, fmt.Errorf("create CEL environment: %w", err)
			}
			_, issues := environment.Parse(expression)
			if issues != nil && issues.Err() != nil {
				return nil, fmt.Errorf("access logging %d CEL expression: %w", index, issues.Err())
			}
			converted.Filter = &expression
		}
		result = append(result, converted)
	}
	return result, nil
}

func convertTelemetryMode(mode telemetryapi.WorkloadMode) (model.TelemetryMode, error) {
	switch mode {
	case telemetryapi.WorkloadMode_CLIENT:
		return model.TelemetryModeClient, nil
	case telemetryapi.WorkloadMode_SERVER:
		return model.TelemetryModeServer, nil
	case telemetryapi.WorkloadMode_CLIENT_AND_SERVER:
		return model.TelemetryModeClientAndServer, nil
	default:
		return 0, fmt.Errorf("unsupported workload mode %d", mode)
	}
}

func convertTelemetryProviderRefs(input []*telemetryapi.ProviderRef) []string {
	result := make([]string, 0, len(input))
	for _, provider := range input {
		if provider == nil {
			result = append(result, "")
			continue
		}
		result = append(result, provider.GetName())
	}
	return result
}

func wrapperBool(input *wrapperspb.BoolValue) *bool {
	if input == nil {
		return nil
	}
	value := input.GetValue()
	return &value
}

func wrapperDouble(input *wrapperspb.DoubleValue) *float64 {
	if input == nil {
		return nil
	}
	value := input.GetValue()
	return &value
}
