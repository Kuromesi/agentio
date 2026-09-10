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

package debug

import (
	"fmt"

	"github.com/openkruise/agentio/pkg/model"
)

func configDebugTelemetry(telemetry model.Telemetry) (configDebugItem, error) {
	metrics := make([]configDebugTelemetryMetrics, 0, len(telemetry.Metrics))
	for _, entry := range telemetry.Metrics {
		metrics = append(metrics, configDebugMetrics(entry))
	}
	tracing := make([]configDebugTelemetryTracing, 0, len(telemetry.Tracing))
	for _, entry := range telemetry.Tracing {
		tracing = append(tracing, configDebugTracing(entry))
	}
	logging := make([]configDebugTelemetryLogging, 0, len(telemetry.AccessLogging))
	for _, entry := range telemetry.AccessLogging {
		logging = append(logging, configDebugLogging(entry))
	}
	spec, err := marshalConfigDebugJSON(configDebugTelemetrySpec{
		TargetGateways: append([]string(nil), telemetry.TargetGateways...),
		Metrics:        metrics,
		Tracing:        tracing,
		AccessLogging:  logging,
	})
	return configDebugItem{
		Kind: "Telemetry",
		Metadata: configDebugMetadata{
			Namespace:         telemetry.Namespace,
			Name:              telemetry.Name,
			Source:            telemetry.Source,
			ResourceVersion:   telemetry.ResourceVersion,
			CreationTimestamp: configDebugTime(telemetry.CreationTime),
		},
		Spec: spec,
	}, err
}

type configDebugTelemetrySpec struct {
	TargetGateways []string                      `json:"targetGateways,omitempty"`
	Metrics        []configDebugTelemetryMetrics `json:"metrics,omitempty"`
	Tracing        []configDebugTelemetryTracing `json:"tracing,omitempty"`
	AccessLogging  []configDebugTelemetryLogging `json:"accessLogging,omitempty"`
}

type configDebugTelemetryMetrics struct {
	Providers         []string                       `json:"providers,omitempty"`
	Overrides         []configDebugTelemetryOverride `json:"overrides,omitempty"`
	ReportingInterval string                         `json:"reportingInterval,omitempty"`
}

type configDebugTelemetryOverride struct {
	Match        configDebugTelemetrySelector               `json:"match"`
	Disabled     *bool                                      `json:"disabled,omitempty"`
	TagOverrides map[string]configDebugTelemetryTagOverride `json:"tagOverrides,omitempty"`
}

type configDebugTelemetrySelector struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Mode string `json:"mode"`
}

type configDebugTelemetryTagOverride struct {
	Operation string `json:"operation"`
	Value     string `json:"value,omitempty"`
}

type configDebugTelemetryTracing struct {
	Mode                         string                           `json:"mode"`
	Providers                    []string                         `json:"providers,omitempty"`
	RandomSamplingPercentage     *float64                         `json:"randomSamplingPercentage,omitempty"`
	DisableSpanReporting         *bool                            `json:"disableSpanReporting,omitempty"`
	CustomTags                   map[string]configDebugTracingTag `json:"customTags,omitempty"`
	UseRequestIDForTraceSampling *bool                            `json:"useRequestIDForTraceSampling,omitempty"`
	EnableIstioTags              *bool                            `json:"enableIstioTags,omitempty"`
}

type configDebugTracingTag struct {
	Kind         string `json:"kind"`
	Name         string `json:"name,omitempty"`
	Value        string `json:"value,omitempty"`
	DefaultValue string `json:"defaultValue,omitempty"`
}

type configDebugTelemetryLogging struct {
	Mode      string   `json:"mode"`
	Providers []string `json:"providers,omitempty"`
	Disabled  *bool    `json:"disabled,omitempty"`
	Filter    *string  `json:"filter,omitempty"`
}

func configDebugMetrics(metrics model.TelemetryMetrics) configDebugTelemetryMetrics {
	result := configDebugTelemetryMetrics{
		Providers: append([]string(nil), metrics.Providers...),
		Overrides: make([]configDebugTelemetryOverride, 0, len(metrics.Overrides)),
	}
	if metrics.ReportingInterval != nil {
		result.ReportingInterval = metrics.ReportingInterval.String()
	}
	for _, override := range metrics.Overrides {
		tags := make(map[string]configDebugTelemetryTagOverride, len(override.TagOverrides))
		for name, tag := range override.TagOverrides {
			tags[name] = configDebugTelemetryTagOverride{
				Operation: configDebugTelemetryTagOperation(tag.Operation),
				Value:     tag.Value,
			}
		}
		result.Overrides = append(result.Overrides, configDebugTelemetryOverride{
			Match: configDebugTelemetrySelector{
				Kind: configDebugTelemetryMetricKind(override.Match.Kind),
				Name: override.Match.Name,
				Mode: configDebugTelemetryMode(override.Match.Mode),
			},
			Disabled:     override.Disabled,
			TagOverrides: tags,
		})
	}
	return result
}

func configDebugTracing(tracing model.TelemetryTracing) configDebugTelemetryTracing {
	tags := make(map[string]configDebugTracingTag, len(tracing.CustomTags))
	for name, tag := range tracing.CustomTags {
		tags[name] = configDebugTracingTag{
			Kind:         configDebugTelemetryTracingTagKind(tag.Kind),
			Name:         tag.Name,
			Value:        tag.Value,
			DefaultValue: tag.DefaultValue,
		}
	}
	return configDebugTelemetryTracing{
		Mode:                         configDebugTelemetryMode(tracing.Mode),
		Providers:                    append([]string(nil), tracing.Providers...),
		RandomSamplingPercentage:     tracing.RandomSamplingPercentage,
		DisableSpanReporting:         tracing.DisableSpanReporting,
		CustomTags:                   tags,
		UseRequestIDForTraceSampling: tracing.UseRequestIDForTraceSampling,
		EnableIstioTags:              tracing.EnableIstioTags,
	}
}

func configDebugLogging(logging model.TelemetryAccessLogging) configDebugTelemetryLogging {
	return configDebugTelemetryLogging{
		Mode:      configDebugTelemetryMode(logging.Mode),
		Providers: append([]string(nil), logging.Providers...),
		Disabled:  logging.Disabled,
		Filter:    logging.Filter,
	}
}

func configDebugTelemetryMode(mode model.TelemetryMode) string {
	switch mode {
	case model.TelemetryModeClient:
		return "CLIENT"
	case model.TelemetryModeServer:
		return "SERVER"
	case model.TelemetryModeClientAndServer:
		return "CLIENT_AND_SERVER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", mode)
	}
}

func configDebugTelemetryMetricKind(kind model.TelemetryMetricKind) string {
	switch kind {
	case model.TelemetryMetricAll:
		return "ALL"
	case model.TelemetryMetricStandard:
		return "STANDARD"
	case model.TelemetryMetricCustom:
		return "CUSTOM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", kind)
	}
}

func configDebugTelemetryTagOperation(operation model.TelemetryTagOperation) string {
	switch operation {
	case model.TelemetryTagRemove:
		return "REMOVE"
	case model.TelemetryTagUpsert:
		return "UPSERT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", operation)
	}
}

func configDebugTelemetryTracingTagKind(kind model.TelemetryTracingTagKind) string {
	switch kind {
	case model.TelemetryTracingTagLiteral:
		return "LITERAL"
	case model.TelemetryTracingTagEnvironment:
		return "ENVIRONMENT"
	case model.TelemetryTracingTagHeader:
		return "HEADER"
	case model.TelemetryTracingTagFormatter:
		return "FORMATTER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", kind)
	}
}
