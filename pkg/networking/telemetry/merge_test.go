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
	"reflect"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/model"
)

func TestSelectGatewayTelemetry(t *testing.T) {
	gateway := model.Gateway{Namespace: "bookinfo", Name: "egress"}
	root := telemetryValue(t, "agentio-system", "root", nil)
	namespace := telemetryValue(t, "bookinfo", "namespace", nil)
	exact := telemetryValue(t, "bookinfo", "exact", []string{"bookinfo/egress"})

	got, err := selectTelemetry(gateway, "agentio-system", []model.Telemetry{exact, root, namespace})
	if err != nil {
		t.Fatal(err)
	}
	if names := telemetryNames(got); !reflect.DeepEqual(names, []string{"agentio-system/root", "bookinfo/namespace", "bookinfo/exact"}) {
		t.Fatalf("selected policies = %v", names)
	}

	for name, policies := range map[string][]model.Telemetry{
		"root conflict":      {root, telemetryValue(t, "agentio-system", "other", nil)},
		"namespace conflict": {namespace, telemetryValue(t, "bookinfo", "other", nil)},
		"exact conflict":     {exact, telemetryValue(t, "bookinfo", "other", []string{"bookinfo/egress"})},
		"unrelated exact":    {telemetryValue(t, "bookinfo", "other", []string{"bookinfo/another"})},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := selectTelemetry(gateway, "agentio-system", policies); err == nil {
				t.Fatal("expected selection failure")
			}
		})
	}
}

func TestAgentioMetricsMergeParity(t *testing.T) {
	disabled := true
	enabled := false
	interval := 15 * time.Second
	policies := []model.Telemetry{
		{Metrics: []model.TelemetryMetrics{{
			Providers: []string{"prometheus"},
			Overrides: []model.TelemetryMetricOverride{{
				Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricAll, Mode: model.TelemetryModeClientAndServer},
				Disabled: &disabled,
			}},
		}}},
		{Metrics: []model.TelemetryMetrics{{
			ReportingInterval: &interval,
			Overrides: []model.TelemetryMetricOverride{
				{
					Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer},
					Disabled: &enabled,
					TagOverrides: map[string]model.TelemetryMetricTagOverride{
						"z-tag": {Operation: model.TelemetryTagUpsert, Value: "value"},
						"a-tag": {Operation: model.TelemetryTagRemove},
					},
				},
				{
					Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricCustom, Name: "custom_metric", Mode: model.TelemetryModeClient},
					Disabled: &enabled,
				},
			},
		}}},
	}

	got := mergeMetrics(policies, []string{"prometheus"})
	want := map[string]metricsConfig{
		"prometheus": {
			ReportingInterval: &interval,
			ClientMetrics: metricConfig{Overrides: []metricsOverride{{
				Name: "custom_metric", Tags: []tagOverride{},
			}}},
			ServerMetrics: metricConfig{Overrides: []metricsOverride{{
				Name: "REQUEST_COUNT",
				Tags: []tagOverride{{Name: "a-tag", Remove: true}, {Name: "z-tag", Value: "value"}},
			}}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeMetrics() = %#v, want %#v", got, want)
	}

	if got := mergeMetrics(nil, []string{"prometheus"}); !reflect.DeepEqual(got, map[string]metricsConfig{"prometheus": {}}) {
		t.Fatalf("default metrics = %#v", got)
	}
}

func TestAgentioLoggingMergeParity(t *testing.T) {
	disabled := true
	serverFilter := "response.code >= 500"
	clientFilter := "true"
	policies := []model.Telemetry{
		{AccessLogging: []model.TelemetryAccessLogging{{
			Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &serverFilter,
		}}},
		{AccessLogging: []model.TelemetryAccessLogging{
			{Mode: model.TelemetryModeServer, Disabled: &disabled},
			{Mode: model.TelemetryModeClient, Providers: []string{"ignored"}, Filter: &clientFilter},
		}},
	}

	got := mergeLogs(policies, []string{"envoy"})
	want := map[string]loggingSpec{"envoy": {Disabled: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeLogs() = %#v, want %#v", got, want)
	}
	if got := mergeLogs(nil, []string{"envoy"}); !reflect.DeepEqual(got, map[string]loggingSpec{"envoy": {}}) {
		t.Fatalf("default logging = %#v", got)
	}

	clientOnly := []model.Telemetry{{AccessLogging: []model.TelemetryAccessLogging{{
		Mode: model.TelemetryModeClient, Providers: []string{"client"},
	}}}}
	if got := mergeLogs(clientOnly, []string{"envoy"}); !reflect.DeepEqual(got, map[string]loggingSpec{"envoy": {}}) {
		t.Fatalf("client-only logging changed server defaults = %#v", got)
	}

	serverFilterAfterClient := "response.code == 503"
	clientThenServer := []model.Telemetry{
		{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeClient, Providers: []string{"client"}}}},
		{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer, Filter: &serverFilterAfterClient}}},
	}
	if got := mergeLogs(clientThenServer, []string{"envoy"}); !reflect.DeepEqual(got, map[string]loggingSpec{
		"envoy": {Filter: &serverFilterAfterClient},
	}) {
		t.Fatalf("client logging changed server provider inheritance = %#v", got)
	}
}

func TestAgentioTracingMergeParity(t *testing.T) {
	sampling := 17.5
	disabled := false
	requestID := false
	istioTags := false
	clientSampling := 99.0
	policies := []model.Telemetry{
		{Tracing: []model.TelemetryTracing{{
			Mode:                     model.TelemetryModeServer,
			Providers:                []string{"zipkin", "ignored"},
			RandomSamplingPercentage: &sampling,
			CustomTags: map[string]model.TelemetryTracingTag{
				"root": {Kind: model.TelemetryTracingTagLiteral, Value: "root"},
			},
			UseRequestIDForTraceSampling: &requestID,
			EnableIstioTags:              &istioTags,
		}}},
		{Tracing: []model.TelemetryTracing{
			{Mode: model.TelemetryModeClient, RandomSamplingPercentage: &clientSampling},
			{
				Mode:                 model.TelemetryModeClientAndServer,
				DisableSpanReporting: &disabled,
				CustomTags: map[string]model.TelemetryTracingTag{
					"child": {Kind: model.TelemetryTracingTagHeader, Name: "x-user", DefaultValue: "unknown"},
				},
			},
		}},
	}

	got := mergeTracing(policies, []string{"default"})
	want := tracingSpec{
		Provider:                 "zipkin",
		RandomSamplingPercentage: &sampling,
		CustomTags: map[string]model.TelemetryTracingTag{
			"child": {Kind: model.TelemetryTracingTagHeader, Name: "x-user", DefaultValue: "unknown"},
		},
		UseRequestIDForTraceSampling: false,
		EnableIstioTags:              false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTracing() = %#v, want %#v", got, want)
	}
	if got := mergeTracing(nil, nil); !got.Disabled {
		t.Fatalf("tracing without provider = %#v, want disabled", got)
	}
}

func telemetryValue(t *testing.T, namespace, name string, targets []string) model.Telemetry {
	t.Helper()
	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: namespace, Name: name, Source: "agentio-system/config-sources",
	}, targets, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func telemetryNames(policies []model.Telemetry) []string {
	result := make([]string, len(policies))
	for index := range policies {
		result[index] = policies[index].LogicalName()
	}
	return result
}
