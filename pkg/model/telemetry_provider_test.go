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

package model

import (
	"testing"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestTelemetryProvidersCloneOwnsProtobufsAndSlices(t *testing.T) {
	providers := TelemetryProviders{
		DefaultMetrics:       []string{"prometheus"},
		DefaultTracing:       []string{"otel"},
		DefaultAccessLogging: []string{"envoy"},
		Providers: []TelemetryProvider{
			{Name: "prometheus", Prometheus: true},
			{
				Name:          "envoy",
				HTTPAccessLog: &accesslogv3.AccessLog{Name: "http"},
				TCPAccessLog:  &accesslogv3.AccessLog{Name: "tcp"},
				Clusters:      []*clusterv3.Cluster{{Name: "collector"}},
			},
			{
				Name: "otel",
				Tracing: &TelemetryTracingProvider{Provider: &tracev3.Tracing_Http{
					Name:       "envoy.tracers.opentelemetry",
					ConfigType: &tracev3.Tracing_Http_TypedConfig{TypedConfig: &anypb.Any{TypeUrl: "example", Value: []byte{1}}},
				}},
			},
		},
	}
	clone := providers.Clone()
	clone.DefaultMetrics[0] = "changed"
	clone.Providers[1].HTTPAccessLog.Name = "changed"
	clone.Providers[1].Clusters[0].Name = "changed"
	clone.Providers[2].Tracing.Provider.Name = "changed"

	if providers.DefaultMetrics[0] != "prometheus" || providers.Providers[1].HTTPAccessLog.Name != "http" ||
		providers.Providers[1].Clusters[0].Name != "collector" ||
		providers.Providers[2].Tracing.Provider.Name != "envoy.tracers.opentelemetry" {
		t.Fatalf("Clone aliases input: %+v", providers)
	}
	if !providers.Equals(providers.Clone()) {
		t.Fatal("provider configuration does not equal its independent clone")
	}
}

func TestTelemetryProviderOverridesClonePreservesPresence(t *testing.T) {
	overrides := TelemetryProviderOverrides{
		Metrics:         OptionalProviderNames{Set: true, Names: []string{}},
		AccessLogging:   OptionalProviderNames{Set: true, Names: []string{"remote"}},
		Providers:       []TelemetryProvider{{Name: "remote", HTTPAccessLog: &accesslogv3.AccessLog{Name: "remote"}}},
		RemoveProviders: []string{"envoy"},
	}
	clone := overrides.Clone()
	clone.AccessLogging.Names[0] = "changed"
	clone.Providers[0].HTTPAccessLog.Name = "changed"
	clone.RemoveProviders[0] = "changed"
	if !overrides.Metrics.Set || overrides.Metrics.Names == nil || len(overrides.Metrics.Names) != 0 {
		t.Fatalf("explicit empty metrics list lost presence: %+v", overrides.Metrics)
	}
	if overrides.AccessLogging.Names[0] != "remote" || overrides.Providers[0].HTTPAccessLog.Name != "remote" ||
		overrides.RemoveProviders[0] != "envoy" {
		t.Fatalf("override clone aliases input: %+v", overrides)
	}
}
