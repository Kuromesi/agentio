// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"testing"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
)

func TestMetricsLoggerSelection(t *testing.T) {
	for _, tt := range []struct {
		name      string
		config    metricConfig
		selection string
		omitted   bool
		invalid   bool
	}{
		{name: "defaults"},
		{name: "disabled", config: metricConfig{Disabled: true}, omitted: true},
		{name: "requests only", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_DURATION", Disabled: true}}}, selection: "requests"},
		{name: "duration only", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}}}, selection: "duration"},
		{name: "both disabled", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}, {Name: "REQUEST_DURATION", Disabled: true}}}, omitted: true},
		{name: "legacy tag removals", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "source_workload", Remove: true}}}, {Name: "REQUEST_DURATION", Tags: []tagOverride{{Name: "response_code", Remove: true}}}}}},
		{name: "unsupported tag", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "tenant", Value: "x"}}}}}, invalid: true},
		{name: "required response code", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "response_code", Remove: true}}}}}, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := buildMetricsLogger(metricsConfig{ServerMetrics: tt.config})
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v", err)
			}
			if tt.invalid {
				return
			}
			if (logger == nil) != tt.omitted {
				t.Fatalf("logger = %v", logger)
			}
			if tt.omitted {
				return
			}
			config := new(udpatypev1.TypedStruct)
			if err := logger.GetTypedConfig().UnmarshalTo(config); err != nil {
				t.Fatal(err)
			}
			if logger.Name != metricsLoggerName ||
				config.TypeUrl != "type.googleapis.com/envoy.extensions.access_loggers.dynamic_modules.v3.DynamicModuleAccessLog" {
				t.Fatalf("wrong module: %v", logger)
			}
			if got := config.Value.GetFields()["logger_config"].GetStructValue().GetFields()["value"].GetStringValue(); got != tt.selection {
				t.Fatalf("selection=%q", got)
			}
		})
	}
}
