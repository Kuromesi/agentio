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

package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	telemetryapi "istio.io/api/telemetry/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const telemetryAPIGroup = "telemetry.istio.io"

func newTelemetriesCollection(
	configMaps krt.Collection[*corev1.ConfigMap],
	rootNamespace string,
	options ...krt.CollectionOption,
) krt.Collection[model.Telemetry] {
	return krt.NewManyCollection(configMaps,
		func(ctx krt.HandlerContext, configMap *corev1.ConfigMap) []model.Telemetry {
			if configMap.Namespace != rootNamespace {
				return nil
			}
			policies, err := decodeTelemetries(configMap)
			if err != nil {
				log.Warn("retain last-known-good Telemetry", "namespace", configMap.Namespace, "configmap", configMap.Name, "error", err)
				ctx.DiscardResult()
				return nil
			}
			return policies
		}, options...)
}

func decodeTelemetries(configMap *corev1.ConfigMap) ([]model.Telemetry, error) {
	if configMap == nil {
		return nil, nil
	}
	if _, selected := configMap.Labels[KubeSourceConfigMapLabel]; !selected {
		return nil, nil
	}
	content := configMap.Data[KubeSourceDataKey]
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}

	decoder := kubeyaml.NewYAMLOrJSONDecoder(strings.NewReader(content), 4096)
	var result []model.Telemetry
	var parseErrors []error
	seen := sets.New[string]()
	for document := 0; ; document++ {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			parseErrors = append(parseErrors, fmt.Errorf("decode document %d: %w", document, err))
			break
		}
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		policies, err := decodeTelemetryDocument(configMap, raw)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("document %d: %w", document, err))
			continue
		}
		for _, policy := range policies {
			if seen.Contains(policy.LogicalName()) {
				parseErrors = append(parseErrors,
					fmt.Errorf("duplicate Telemetry %s in one ConfigMap", policy.LogicalName()))
				continue
			}
			seen.Insert(policy.LogicalName())
			result = append(result, policy)
		}
	}
	return result, errors.Join(parseErrors...)
}

func decodeTelemetryDocument(configMap *corev1.ConfigMap, raw json.RawMessage) ([]model.Telemetry, error) {
	var document configSourceDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode Kubernetes object: %w", err)
	}
	if document.Kind == "List" {
		var result []model.Telemetry
		var parseErrors []error
		for index, item := range document.Items {
			policies, err := decodeTelemetryDocument(configMap, item)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("list item %d: %w", index, err))
				continue
			}
			result = append(result, policies...)
		}
		return result, errors.Join(parseErrors...)
	}
	if document.Kind != "Telemetry" || apiGroup(document.APIVersion) != telemetryAPIGroup {
		return nil, nil
	}
	if document.Metadata.Namespace == "" || document.Metadata.Name == "" {
		return nil, fmt.Errorf("Telemetry metadata namespace and name are required")
	}
	if len(document.Spec) == 0 || string(document.Spec) == "null" {
		return nil, fmt.Errorf("Telemetry %s/%s spec is required", document.Metadata.Namespace, document.Metadata.Name)
	}
	normalized, err := normalizeLegacyTelemetryJSON(document.Spec)
	if err != nil {
		return nil, fmt.Errorf("normalize Telemetry %s/%s spec: %w", document.Metadata.Namespace, document.Metadata.Name, err)
	}
	spec := &telemetryapi.Telemetry{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(normalized, spec); err != nil {
		return nil, fmt.Errorf("decode Telemetry %s/%s spec: %w", document.Metadata.Namespace, document.Metadata.Name, err)
	}
	policy, err := convertIstioTelemetry(telemetrySourceMetadata{
		Namespace:       document.Metadata.Namespace,
		Name:            document.Metadata.Name,
		Source:          configMap.Namespace + "/" + configMap.Name,
		ResourceVersion: configMap.ResourceVersion,
		CreationTime:    document.Metadata.CreationTimestamp.Time,
	}, spec)
	if err != nil {
		return nil, fmt.Errorf("convert Telemetry %s/%s: %w", document.Metadata.Namespace, document.Metadata.Name, err)
	}
	return []model.Telemetry{policy}, nil
}

// The deployed Agentio chart historically placed MetricsOverrides.mode beside
// match rather than inside it. Both forms mean the same thing for its
// CLIENT_AND_SERVER default. Normalize only this known compatibility shape and
// leave every other unknown field for strict protojson rejection.
func normalizeLegacyTelemetryJSON(spec json.RawMessage) (json.RawMessage, error) {
	var object map[string]any
	if err := json.Unmarshal(spec, &object); err != nil {
		return nil, err
	}
	metrics, _ := object["metrics"].([]any)
	for metricIndex, rawMetric := range metrics {
		metric, ok := rawMetric.(map[string]any)
		if !ok {
			continue
		}
		overrides, _ := metric["overrides"].([]any)
		for overrideIndex, rawOverride := range overrides {
			override, ok := rawOverride.(map[string]any)
			if !ok {
				continue
			}
			mode, found := override["mode"]
			if !found {
				continue
			}
			match, ok := override["match"].(map[string]any)
			if !ok {
				match = map[string]any{}
				override["match"] = match
			}
			if existing, found := match["mode"]; found && existing != mode {
				return nil, fmt.Errorf("metrics %d override %d specifies conflicting mode values", metricIndex, overrideIndex)
			}
			match["mode"] = mode
			delete(override, "mode")
		}
	}
	return json.Marshal(object)
}
