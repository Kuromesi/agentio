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
	"strings"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

func resolveTelemetryProviders(overrides *model.TelemetryProviderOverrides) (model.TelemetryProviders, error) {
	result := defaultTelemetryProviders()
	if overrides != nil {
		input := overrides.Clone()
		providers := make(map[string]model.TelemetryProvider, len(result.Providers)+len(input.Providers))
		for _, provider := range result.Providers {
			providers[strings.ToLower(provider.Name)] = provider
		}
		removed := sets.NewWithLength[string](len(input.RemoveProviders))
		for _, name := range input.RemoveProviders {
			key := strings.ToLower(strings.TrimSpace(name))
			if key == "" {
				return model.TelemetryProviders{}, fmt.Errorf("removed provider name is required")
			}
			if removed.Contains(key) {
				return model.TelemetryProviders{}, fmt.Errorf("removed provider %q is duplicated", name)
			}
			removed.Insert(key)
			delete(providers, key)
		}
		replacements := sets.NewWithLength[string](len(input.Providers))
		for _, provider := range input.Providers {
			key := strings.ToLower(strings.TrimSpace(provider.Name))
			if key == "" {
				return model.TelemetryProviders{}, fmt.Errorf("provider name is required")
			}
			if replacements.Contains(key) {
				return model.TelemetryProviders{}, fmt.Errorf("provider %q is a duplicate override", provider.Name)
			}
			replacements.Insert(key)
			providers[key] = provider.Clone()
		}
		result.Providers = result.Providers[:0]
		for _, provider := range providers {
			result.Providers = append(result.Providers, provider)
		}
		if input.Metrics.Set {
			result.DefaultMetrics = input.Metrics.Names
		}
		if input.Tracing.Set {
			result.DefaultTracing = input.Tracing.Names
		}
		if input.AccessLogging.Set {
			result.DefaultAccessLogging = input.AccessLogging.Names
		}
	}
	sort.Slice(result.Providers, func(i, j int) bool {
		return strings.ToLower(result.Providers[i].Name) < strings.ToLower(result.Providers[j].Name)
	})
	if err := validateProviders(result); err != nil {
		return model.TelemetryProviders{}, err
	}
	return result, nil
}

func validateProviders(configuration model.TelemetryProviders) error {
	providers := make(map[string]model.TelemetryProvider, len(configuration.Providers))
	clusters := make(map[string]string)
	for _, provider := range configuration.Providers {
		key := strings.ToLower(strings.TrimSpace(provider.Name))
		if key == "" {
			return fmt.Errorf("provider name is required")
		}
		if _, duplicate := providers[key]; duplicate {
			return fmt.Errorf("provider %q is duplicated", provider.Name)
		}
		if !provider.Prometheus && provider.HTTPAccessLog == nil && provider.TCPAccessLog == nil && provider.Tracing == nil {
			return fmt.Errorf("provider %q has no Telemetry capability", provider.Name)
		}
		if provider.HTTPAccessLog != nil {
			if err := provider.HTTPAccessLog.ValidateAll(); err != nil {
				return fmt.Errorf("provider %q HTTP access log: %w", provider.Name, err)
			}
		}
		if provider.TCPAccessLog != nil {
			if err := provider.TCPAccessLog.ValidateAll(); err != nil {
				return fmt.Errorf("provider %q TCP access log: %w", provider.Name, err)
			}
		}
		if provider.Tracing != nil {
			if provider.Tracing.Provider == nil {
				return fmt.Errorf("provider %q tracing payload is required", provider.Name)
			}
			if err := provider.Tracing.Provider.ValidateAll(); err != nil {
				return fmt.Errorf("provider %q tracing payload: %w", provider.Name, err)
			}
		}
		for _, cluster := range provider.Clusters {
			if cluster == nil || cluster.GetName() == "" {
				return fmt.Errorf("provider %q cluster name is required", provider.Name)
			}
			if owner, duplicate := clusters[cluster.GetName()]; duplicate {
				return fmt.Errorf("provider %q cluster %q duplicates provider %q", provider.Name, cluster.GetName(), owner)
			}
			clusters[cluster.GetName()] = provider.Name
			if err := cluster.ValidateAll(); err != nil {
				return fmt.Errorf("provider %q cluster %q: %w", provider.Name, cluster.GetName(), err)
			}
		}
		providers[key] = provider
	}
	if err := validateDefaultProviderNames("metrics", configuration.DefaultMetrics, providers, func(p model.TelemetryProvider) bool { return p.Prometheus }); err != nil {
		return err
	}
	if err := validateDefaultProviderNames("tracing", configuration.DefaultTracing, providers, func(p model.TelemetryProvider) bool { return p.Tracing != nil }); err != nil {
		return err
	}
	return validateDefaultProviderNames("access logging", configuration.DefaultAccessLogging, providers,
		func(p model.TelemetryProvider) bool { return p.HTTPAccessLog != nil && p.TCPAccessLog != nil })
}

func validateDefaultProviderNames(
	signal string,
	names []string,
	providers map[string]model.TelemetryProvider,
	supports func(model.TelemetryProvider) bool,
) error {
	seen := sets.NewWithLength[string](len(names))
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		provider, found := providers[key]
		if !found {
			return fmt.Errorf("default %s provider %q does not exist", signal, name)
		}
		if seen.Contains(key) {
			return fmt.Errorf("default %s provider %q is duplicated", signal, name)
		}
		seen.Insert(key)
		if !supports(provider) {
			return fmt.Errorf("provider %q does not support %s", name, signal)
		}
	}
	return nil
}
