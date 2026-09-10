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
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/model"
)

type configDebugFilter struct {
	Kind      string
	Namespace string
	Name      string
	Pretty    bool
}

type configDebugResponse struct {
	GeneratedAt  time.Time            `json:"generatedAt"`
	Synced       bool                 `json:"synced"`
	CountsByKind map[string]int       `json:"countsByKind"`
	Items        []configDebugItem    `json:"items"`
	Failures     []configDebugFailure `json:"failures"`
}

type configDebugItem struct {
	Kind     string              `json:"kind"`
	Metadata configDebugMetadata `json:"metadata"`
	Spec     json.RawMessage     `json:"spec"`
}

type configDebugMetadata struct {
	Namespace         string     `json:"namespace,omitempty"`
	Name              string     `json:"name"`
	Source            string     `json:"source,omitempty"`
	ResourceVersion   string     `json:"resourceVersion,omitempty"`
	CreationTimestamp *time.Time `json:"creationTimestamp,omitempty"`
}

type configDebugFailure struct {
	Key     string `json:"key"`
	Message string `json:"message"`
}

func configDebugSnapshotAt(
	now time.Time,
	sources Sources,
	resourceCompiler *compiler.Compiler,
	filter configDebugFilter,
) (configDebugResponse, error) {
	result := configDebugResponse{
		GeneratedAt:  now.UTC().Truncate(time.Second),
		Synced:       configDebugInputsSynced(sources) && resourceCompiler.HasSynced(),
		CountsByKind: make(map[string]int),
		Items:        make([]configDebugItem, 0),
		Failures:     configDebugFailures(resourceCompiler.Failures()),
	}
	appendItem := func(item configDebugItem) {
		if !configDebugItemMatches(item, filter) {
			return
		}
		result.Items = append(result.Items, item)
		result.CountsByKind[item.Kind]++
	}

	for _, configuration := range sources.AgentioConfig.List() {
		item, err := configDebugAgentioConfig(configuration)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt AgentioConfig %q: %w", configuration.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, policy := range sources.TrafficPolicies.List() {
		item, err := configDebugTrafficPolicy(policy)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt TrafficPolicy %q: %w", policy.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, profile := range sources.SecurityProfiles.List() {
		item, err := configDebugSecurityProfile(profile)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt SecurityProfile %q: %w", profile.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, gateway := range sources.Gateways.List() {
		item, err := configDebugGateway(gateway)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt Gateway %q: %w", gateway.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, patch := range sources.GatewayPatches.List() {
		item, err := configDebugGatewayPatch(patch)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt EnvoyFilter %q: %w", patch.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, telemetry := range sources.Telemetry.List() {
		item, err := configDebugTelemetry(telemetry)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt Telemetry %q: %w", telemetry.ResourceName(), err)
		}
		appendItem(item)
	}

	sort.Slice(result.Items, func(left, right int) bool {
		a, b := result.Items[left], result.Items[right]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Metadata.Namespace != b.Metadata.Namespace {
			return a.Metadata.Namespace < b.Metadata.Namespace
		}
		if a.Metadata.Name != b.Metadata.Name {
			return a.Metadata.Name < b.Metadata.Name
		}
		return a.Metadata.Source < b.Metadata.Source
	})
	return result, nil
}

func configDebugInputsSynced(sources Sources) bool {
	return sources.AgentioConfig.HasSynced() &&
		sources.TrafficPolicies.HasSynced() &&
		sources.SecurityProfiles.HasSynced() &&
		sources.Gateways.HasSynced() &&
		sources.GatewayPatches.HasSynced() &&
		sources.Telemetry.HasSynced()
}

func configDebugFailures(failures map[string]string) []configDebugFailure {
	keys := make([]string, 0, len(failures))
	for key := range failures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]configDebugFailure, 0, len(keys))
	for _, key := range keys {
		result = append(result, configDebugFailure{Key: key, Message: failures[key]})
	}
	return result
}

func configDebugItemMatches(item configDebugItem, filter configDebugFilter) bool {
	return (filter.Kind == "" || item.Kind == filter.Kind) &&
		(filter.Namespace == "" || item.Metadata.Namespace == filter.Namespace) &&
		(filter.Name == "" || item.Metadata.Name == filter.Name)
}

func configDebugAgentioConfig(configuration model.AgentioConfiguration) (configDebugItem, error) {
	spec, err := marshalConfigDebugProto(configuration.Value)
	return configDebugItem{
		Kind: "AgentioConfig",
		Metadata: configDebugMetadata{
			Name:            configuration.ResourceName(),
			ResourceVersion: configuration.ResourceVersion,
		},
		Spec: spec,
	}, err
}

func configDebugTrafficPolicy(policy model.TrafficPolicy) (configDebugItem, error) {
	kind, namespace := "TrafficPolicy", policy.Namespace
	if policy.Global {
		kind, namespace = "GlobalTrafficPolicy", ""
	}
	spec, err := marshalConfigDebugJSON(policy.Spec)
	return configDebugItem{
		Kind: kind,
		Metadata: configDebugMetadata{
			Namespace:         namespace,
			Name:              policy.Name,
			CreationTimestamp: configDebugTime(policy.CreationTime),
		},
		Spec: spec,
	}, err
}

func configDebugSecurityProfile(profile model.SecurityProfile) (configDebugItem, error) {
	kind, namespace := "SecurityProfile", profile.Namespace
	if profile.Global {
		kind, namespace = "GlobalSecurityProfile", ""
	}
	safeSpec := profile.Spec.DeepCopy()
	redactConfigDebugSecurityProfile(safeSpec)
	spec, err := marshalConfigDebugJSON(safeSpec)
	return configDebugItem{
		Kind: kind,
		Metadata: configDebugMetadata{
			Namespace:         namespace,
			Name:              profile.Name,
			CreationTimestamp: configDebugTime(profile.CreationTime),
		},
		Spec: spec,
	}, err
}

func configDebugGateway(gateway model.Gateway) (configDebugItem, error) {
	spec, err := marshalConfigDebugProto(gateway.Config)
	return configDebugItem{
		Kind: "Gateway",
		Metadata: configDebugMetadata{
			Namespace: gateway.Namespace,
			Name:      gateway.Name,
			Source:    string(gateway.Source),
		},
		Spec: spec,
	}, err
}

func configDebugTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}
