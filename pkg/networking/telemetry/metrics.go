// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/util/protoutil"
)

const metricsLoggerName = "envoy.access_loggers.dynamic_modules"

// The gateway module exposes request count by response_code and aggregate duration.
// Other request/TCP statistics remain available through Envoy's native metrics.
func buildMetricsLogger(configuration metricsConfig) (*accesslogv3.AccessLog, error) {
	if configuration.ServerMetrics.Disabled {
		return nil, nil
	}
	requests, duration := true, true
	for _, override := range configuration.ServerMetrics.Overrides {
		switch override.Name {
		case "REQUEST_COUNT":
			requests = !override.Disabled
		case "REQUEST_DURATION":
			duration = !override.Disabled
		default:
			// Removing absent dimensions/metrics is harmless during migration.
			if override.Disabled {
				continue
			}
			for _, tag := range override.Tags {
				if !tag.Remove {
					return nil, fmt.Errorf("metric %s does not support dimension %s", override.Name, tag.Name)
				}
			}
			continue
		}
		if override.Disabled {
			continue
		}
		for _, tag := range override.Tags {
			if !tag.Remove || (override.Name == "REQUEST_COUNT" && tag.Name == "response_code") {
				return nil, fmt.Errorf("metric %s does not support overriding dimension %s", override.Name, tag.Name)
			}
		}
	}
	if !requests && !duration {
		return nil, nil
	}
	selection := ""
	if !requests {
		selection = "duration"
	} else if !duration {
		selection = "requests"
	}
	// The pinned Go API predates the native access logger; TypedStruct lets Envoy
	// decode its current schema without coupling control-plane upgrades to the SDK.
	fields, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name": "agentio_gateway_metrics",
			"module": map[string]any{
				"local": map[string]any{"filename": "/usr/local/lib/libagentio_gateway_metrics.so"},
			},
			"metrics_namespace": "agentio_gateway",
		},
		"logger_name":   "metrics",
		"logger_config": map[string]any{"@type": "type.googleapis.com/google.protobuf.StringValue", "value": selection},
	})
	if err != nil {
		return nil, err
	}
	typed, err := protoutil.MarshalAny(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.access_loggers.dynamic_modules.v3.DynamicModuleAccessLog",
		Value:   fields,
	})
	if err != nil {
		return nil, err
	}
	return &accesslogv3.AccessLog{
		Name:       metricsLoggerName,
		ConfigType: &accesslogv3.AccessLog_TypedConfig{TypedConfig: typed},
	}, nil
}
