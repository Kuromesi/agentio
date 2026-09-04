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
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

var allMetrics = []string{
	"GRPC_REQUEST_MESSAGES",
	"GRPC_RESPONSE_MESSAGES",
	"REQUEST_COUNT",
	"REQUEST_DURATION",
	"REQUEST_SIZE",
	"RESPONSE_SIZE",
	"TCP_CLOSED_CONNECTIONS",
	"TCP_OPENED_CONNECTIONS",
	"TCP_RECEIVED_BYTES",
	"TCP_SENT_BYTES",
}

type metricsConfig struct {
	ClientMetrics     metricConfig
	ServerMetrics     metricConfig
	ReportingInterval *time.Duration
}

type metricConfig struct {
	Disabled  bool
	Overrides []metricsOverride
}

type metricsOverride struct {
	Name     string
	Disabled bool
	Tags     []tagOverride
}

type tagOverride struct {
	Name   string
	Remove bool
	Value  string
}

type loggingSpec struct {
	Disabled bool
	Filter   *string
}

type tracingSpec struct {
	Provider                     string
	Disabled                     bool
	RandomSamplingPercentage     *float64
	CustomTags                   map[string]model.TelemetryTracingTag
	UseRequestIDForTraceSampling bool
	EnableIstioTags              bool
}

func selectTelemetry(gateway model.Gateway, rootNamespace string, candidates []model.Telemetry) ([]model.Telemetry, error) {
	var root, namespace, exact []model.Telemetry
	for _, policy := range candidates {
		if err := policy.ValidateForUse(); err != nil {
			return nil, fmt.Errorf("Telemetry %s: %w", policy.ResourceName(), err)
		}
		switch {
		case len(policy.TargetGateways) > 0:
			if !slices.Contains(policy.TargetGateways, gateway.ResourceName()) {
				return nil, fmt.Errorf("Telemetry %s does not target Gateway %s", policy.ResourceName(), gateway.ResourceName())
			}
			exact = append(exact, policy)
		case policy.Namespace == rootNamespace:
			root = append(root, policy)
		case policy.Namespace == gateway.Namespace:
			namespace = append(namespace, policy)
		default:
			return nil, fmt.Errorf("Telemetry %s is outside Gateway %s inheritance", policy.ResourceName(), gateway.ResourceName())
		}
	}
	if rootNamespace == gateway.Namespace {
		root = append(root, namespace...)
		namespace = nil
	}
	for _, layer := range []struct {
		name     string
		policies []model.Telemetry
	}{{"root", root}, {"namespace", namespace}, {"Gateway", exact}} {
		if len(layer.policies) > 1 {
			names := make([]string, len(layer.policies))
			for index := range layer.policies {
				names[index] = layer.policies[index].ResourceName()
			}
			sort.Strings(names)
			return nil, fmt.Errorf("Gateway %s has conflicting %s Telemetry entries: %s", gateway.ResourceName(), layer.name, strings.Join(names, ", "))
		}
	}
	result := make([]model.Telemetry, 0, 3)
	result = append(result, root...)
	result = append(result, namespace...)
	result = append(result, exact...)
	return result, nil
}

// mergeMetrics applies policy entries in order. Later entries override earlier
// entries, while a missing provider list inherits its parent list rather than
// deep-merging it.
func mergeMetrics(policies []model.Telemetry, defaultProviders []string) map[string]metricsConfig {
	type metricValue struct {
		Disabled     *bool
		TagOverrides map[string]model.TelemetryMetricTagOverride
	}
	providers := map[string]map[model.TelemetryMode]map[string]metricValue{}
	metrics := flattenMetrics(policies)
	if len(metrics) == 0 {
		for _, provider := range defaultProviders {
			providers[provider] = map[model.TelemetryMode]map[string]metricValue{}
		}
	}

	finalProviders := slices.Clone(defaultProviders)
	for _, entry := range metrics {
		if len(entry.Providers) > 0 {
			finalProviders = entry.Providers
		}
	}
	inScope := stringSet(finalProviders)
	parentProviders := slices.Clone(defaultProviders)
	disabledAll := sets.New[string]()
	reportingIntervals := map[string]*time.Duration{}
	for _, entry := range metrics {
		providerNames := entry.Providers
		if len(providerNames) == 0 {
			providerNames = parentProviders
		}
		parentProviders = providerNames
		for _, provider := range providerNames {
			if !inScope.Contains(provider) {
				continue
			}
			if entry.ReportingInterval != nil {
				value := *entry.ReportingInterval
				reportingIntervals[provider] = &value
			}
			if _, found := providers[provider]; !found {
				providers[provider] = map[model.TelemetryMode]map[string]metricValue{
					model.TelemetryModeClient: {}, model.TelemetryModeServer: {},
				}
			}
			for _, override := range entry.Overrides {
				for _, mode := range workloadModes(override.Match.Mode) {
					key := providerModeKey(provider, mode)
					if override.Match.Kind == model.TelemetryMetricAll && boolValue(override.Disabled) {
						disabledAll.Insert(key)
						continue
					}
					disabledAll.Delete(key)
					for _, metricName := range metricMatches(override.Match) {
						current := providers[provider][mode][metricName]
						if override.Disabled != nil {
							value := *override.Disabled
							current.Disabled = &value
						}
						if len(override.TagOverrides) > 0 {
							if current.TagOverrides == nil {
								current.TagOverrides = map[string]model.TelemetryMetricTagOverride{}
							}
							maps.Copy(current.TagOverrides, override.TagOverrides)
						}
						providers[provider][mode][metricName] = current
					}
				}
			}
		}
	}

	result := map[string]metricsConfig{}
	for provider, modes := range providers {
		configuration := metricsConfig{ReportingInterval: reportingIntervals[provider]}
		for _, mode := range []model.TelemetryMode{model.TelemetryModeClient, model.TelemetryModeServer} {
			metricConfiguration := metricConfig{}
			if disabledAll.Contains(providerModeKey(provider, mode)) {
				metricConfiguration.Disabled = true
			} else {
				for metricName, value := range modes[mode] {
					tags := make([]tagOverride, 0, len(value.TagOverrides))
					for name, tag := range value.TagOverrides {
						tags = append(tags, tagOverride{
							Name: name, Remove: tag.Operation == model.TelemetryTagRemove, Value: tag.Value,
						})
					}
					sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
					metricConfiguration.Overrides = append(metricConfiguration.Overrides, metricsOverride{
						Name: metricName, Disabled: boolValue(value.Disabled), Tags: tags,
					})
				}
				sort.Slice(metricConfiguration.Overrides, func(i, j int) bool {
					return metricConfiguration.Overrides[i].Name < metricConfiguration.Overrides[j].Name
				})
			}
			if mode == model.TelemetryModeClient {
				configuration.ClientMetrics = metricConfiguration
			} else {
				configuration.ServerMetrics = metricConfiguration
			}
		}
		result[provider] = configuration
	}
	return result
}

func mergeLogs(policies []model.Telemetry, defaultProviders []string) map[string]loggingSpec {
	if !hasServerLogging(policies) {
		result := make(map[string]loggingSpec, len(defaultProviders))
		for _, provider := range defaultProviders {
			result[provider] = loggingSpec{}
		}
		return result
	}
	providerNames := slices.Clone(defaultProviders)
	filters := map[string]*string{}
	parentProviders := slices.Clone(defaultProviders)
	for _, policy := range policies {
		layerProviders := sets.New[string]()
		for _, entry := range policy.AccessLogging {
			if !serverMode(entry.Mode) {
				continue
			}
			providers := entry.Providers
			if len(providers) == 0 {
				providers = parentProviders
			}
			parentProviders = providers
			for _, provider := range providers {
				layerProviders.Insert(provider)
				filters[provider] = cloneString(entry.Filter)
			}
		}
		if len(layerProviders) > 0 {
			providerNames = sortedSet(layerProviders)
		}
	}
	inScope := stringSet(providerNames)
	parentProviders = slices.Clone(defaultProviders)
	result := map[string]loggingSpec{}
	for _, policy := range policies {
		for _, entry := range policy.AccessLogging {
			if !serverMode(entry.Mode) {
				continue
			}
			providers := entry.Providers
			if len(providers) == 0 {
				providers = parentProviders
			}
			parentProviders = providers
			for _, provider := range providers {
				if !inScope.Contains(provider) {
					continue
				}
				if boolValue(entry.Disabled) {
					result[provider] = loggingSpec{Disabled: true}
					continue
				}
				result[provider] = loggingSpec{Filter: cloneString(filters[provider])}
			}
		}
	}
	return result
}

func mergeTracing(policies []model.Telemetry, defaultProviders []string) tracingSpec {
	result := tracingSpec{UseRequestIDForTraceSampling: true, EnableIstioTags: true}
	if len(defaultProviders) > 0 {
		result.Provider = defaultProviders[0]
	}
	for _, policy := range policies {
		for _, entry := range policy.Tracing {
			if !serverMode(entry.Mode) {
				continue
			}
			if len(entry.Providers) > 0 {
				result.Provider = entry.Providers[0]
			}
			if entry.DisableSpanReporting != nil {
				result.Disabled = *entry.DisableSpanReporting
			}
			if entry.CustomTags != nil {
				result.CustomTags = make(map[string]model.TelemetryTracingTag, len(entry.CustomTags))
				maps.Copy(result.CustomTags, entry.CustomTags)
			}
			if entry.RandomSamplingPercentage != nil {
				value := *entry.RandomSamplingPercentage
				result.RandomSamplingPercentage = &value
			}
			if entry.UseRequestIDForTraceSampling != nil {
				result.UseRequestIDForTraceSampling = *entry.UseRequestIDForTraceSampling
			}
			if entry.EnableIstioTags != nil {
				result.EnableIstioTags = *entry.EnableIstioTags
			}
		}
	}
	if result.Provider == "" {
		result.Disabled = true
	}
	return result
}

func flattenMetrics(policies []model.Telemetry) []model.TelemetryMetrics {
	var result []model.TelemetryMetrics
	for _, policy := range policies {
		result = append(result, policy.Metrics...)
	}
	return result
}

func hasServerLogging(policies []model.Telemetry) bool {
	for _, policy := range policies {
		for _, entry := range policy.AccessLogging {
			if serverMode(entry.Mode) {
				return true
			}
		}
	}
	return false
}

func workloadModes(mode model.TelemetryMode) []model.TelemetryMode {
	if mode == model.TelemetryModeClient || mode == model.TelemetryModeServer {
		return []model.TelemetryMode{mode}
	}
	return []model.TelemetryMode{model.TelemetryModeClient, model.TelemetryModeServer}
}

func serverMode(mode model.TelemetryMode) bool {
	return mode == model.TelemetryModeServer || mode == model.TelemetryModeClientAndServer
}

func metricMatches(selector model.TelemetryMetricSelector) []string {
	if selector.Kind == model.TelemetryMetricAll {
		return allMetrics
	}
	return []string{selector.Name}
}

func boolValue(value *bool) bool { return value != nil && *value }

func providerModeKey(provider string, mode model.TelemetryMode) string {
	return fmt.Sprintf("%s/%d", provider, mode)
}

func stringSet(values []string) sets.Set[string] {
	result := sets.NewWithLength[string](len(values))
	for _, value := range values {
		result.Insert(value)
	}
	return result
}

func sortedSet(values sets.Set[string]) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
