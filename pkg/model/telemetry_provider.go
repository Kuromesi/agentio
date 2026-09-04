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
	"slices"
	"strings"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"google.golang.org/protobuf/proto"
)

// OptionalProviderNames distinguishes an omitted provider default from an
// explicitly empty default list.
type OptionalProviderNames struct {
	Set   bool
	Names []string
}

func (o OptionalProviderNames) Clone() OptionalProviderNames {
	return OptionalProviderNames{Set: o.Set, Names: slices.Clone(o.Names)}
}

// TelemetryTracingProvider is an Envoy-native tracing capability supplied by
// one source adapter. Telemetry still owns sampling and custom tags.
type TelemetryTracingProvider struct {
	Provider          *tracev3.Tracing_Http
	SpawnUpstreamSpan bool
	MaxPathTagLength  uint32
	CustomSampler     bool
}

func (p *TelemetryTracingProvider) Clone() *TelemetryTracingProvider {
	if p == nil {
		return nil
	}
	result := &TelemetryTracingProvider{
		SpawnUpstreamSpan: p.SpawnUpstreamSpan,
		MaxPathTagLength:  p.MaxPathTagLength,
		CustomSampler:     p.CustomSampler,
	}
	if p.Provider != nil {
		result.Provider = proto.Clone(p.Provider).(*tracev3.Tracing_Http)
	}
	return result
}

// TelemetryProvider is a source-neutral set of Envoy capabilities. It is not
// a copy of MeshConfig's extension-provider oneof.
type TelemetryProvider struct {
	Name          string
	Prometheus    bool
	HTTPAccessLog *accesslogv3.AccessLog
	TCPAccessLog  *accesslogv3.AccessLog
	Tracing       *TelemetryTracingProvider
	Clusters      []*clusterv3.Cluster
}

func (p TelemetryProvider) Clone() TelemetryProvider {
	result := TelemetryProvider{
		Name:       p.Name,
		Prometheus: p.Prometheus,
		Tracing:    p.Tracing.Clone(),
		Clusters:   make([]*clusterv3.Cluster, len(p.Clusters)),
	}
	if p.HTTPAccessLog != nil {
		result.HTTPAccessLog = proto.Clone(p.HTTPAccessLog).(*accesslogv3.AccessLog)
	}
	if p.TCPAccessLog != nil {
		result.TCPAccessLog = proto.Clone(p.TCPAccessLog).(*accesslogv3.AccessLog)
	}
	for index, cluster := range p.Clusters {
		if cluster != nil {
			result.Clusters[index] = proto.Clone(cluster).(*clusterv3.Cluster)
		}
	}
	return result
}

func (p TelemetryProvider) equal(other TelemetryProvider) bool {
	if p.Name != other.Name || p.Prometheus != other.Prometheus ||
		!proto.Equal(p.HTTPAccessLog, other.HTTPAccessLog) || !proto.Equal(p.TCPAccessLog, other.TCPAccessLog) ||
		!equalTracingProvider(p.Tracing, other.Tracing) || len(p.Clusters) != len(other.Clusters) {
		return false
	}
	for index := range p.Clusters {
		if !proto.Equal(p.Clusters[index], other.Clusters[index]) {
			return false
		}
	}
	return true
}

func equalTracingProvider(left, right *TelemetryTracingProvider) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.SpawnUpstreamSpan == right.SpawnUpstreamSpan &&
		left.MaxPathTagLength == right.MaxPathTagLength && left.CustomSampler == right.CustomSampler &&
		proto.Equal(left.Provider, right.Provider)
}

type TelemetryProviders struct {
	DefaultMetrics       []string
	DefaultTracing       []string
	DefaultAccessLogging []string
	Providers            []TelemetryProvider
}

func (p TelemetryProviders) Clone() TelemetryProviders {
	result := TelemetryProviders{
		DefaultMetrics:       slices.Clone(p.DefaultMetrics),
		DefaultTracing:       slices.Clone(p.DefaultTracing),
		DefaultAccessLogging: slices.Clone(p.DefaultAccessLogging),
		Providers:            make([]TelemetryProvider, len(p.Providers)),
	}
	for index, provider := range p.Providers {
		result.Providers[index] = provider.Clone()
	}
	return result
}

func (p TelemetryProviders) Provider(name string) *TelemetryProvider {
	for index := range p.Providers {
		if strings.EqualFold(p.Providers[index].Name, name) {
			return &p.Providers[index]
		}
	}
	return nil
}

func (p TelemetryProviders) Equals(other TelemetryProviders) bool {
	if !slices.Equal(p.DefaultMetrics, other.DefaultMetrics) ||
		!slices.Equal(p.DefaultTracing, other.DefaultTracing) ||
		!slices.Equal(p.DefaultAccessLogging, other.DefaultAccessLogging) || len(p.Providers) != len(other.Providers) {
		return false
	}
	for index := range p.Providers {
		if !p.Providers[index].equal(other.Providers[index]) {
			return false
		}
	}
	return true
}

type TelemetryProviderOverrides struct {
	Metrics         OptionalProviderNames
	Tracing         OptionalProviderNames
	AccessLogging   OptionalProviderNames
	Providers       []TelemetryProvider
	RemoveProviders []string
}

func (o TelemetryProviderOverrides) Clone() TelemetryProviderOverrides {
	result := TelemetryProviderOverrides{
		Metrics:         o.Metrics.Clone(),
		Tracing:         o.Tracing.Clone(),
		AccessLogging:   o.AccessLogging.Clone(),
		Providers:       make([]TelemetryProvider, len(o.Providers)),
		RemoveProviders: slices.Clone(o.RemoveProviders),
	}
	for index, provider := range o.Providers {
		result.Providers[index] = provider.Clone()
	}
	return result
}
