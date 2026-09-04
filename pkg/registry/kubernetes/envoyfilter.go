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
	networking "istio.io/api/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

const (
	KubeSourceConfigMapLabel = "manifests.agents.kruise.io/kube-source"
	KubeSourceDataKey        = "sources"
	envoyFilterAPIGroup      = "networking.istio.io"
)

type configSourceDocument struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       json.RawMessage   `json:"spec"`
	Items      []json.RawMessage `json:"items"`
}

func newEnvoyFiltersCollection(
	configMaps krt.Collection[*corev1.ConfigMap],
	rootNamespace string,
	options ...krt.CollectionOption,
) krt.Collection[model.GatewayPatch] {
	return krt.NewManyCollection(configMaps,
		func(ctx krt.HandlerContext, configMap *corev1.ConfigMap) []model.GatewayPatch {
			if configMap.Namespace != rootNamespace {
				return nil
			}
			filters, err := decodeEnvoyFilters(configMap)
			if err != nil {
				log.Warn("retain last-known-good EnvoyFilters", "namespace", configMap.Namespace, "configmap", configMap.Name, "error", err)
				ctx.DiscardResult()
				return nil
			}
			return filters
		}, options...)
}

func decodeEnvoyFilters(configMap *corev1.ConfigMap) ([]model.GatewayPatch, error) {
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
	var result []model.GatewayPatch
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
		filters, err := decodeEnvoyFilterDocument(configMap, raw)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("document %d: %w", document, err))
			continue
		}
		for _, filter := range filters {
			if seen.Contains(filter.LogicalName()) {
				parseErrors = append(parseErrors,
					fmt.Errorf("duplicate EnvoyFilter %s in one ConfigMap", filter.LogicalName()))
				continue
			}
			seen.Insert(filter.LogicalName())
			result = append(result, filter)
		}
	}
	return result, errors.Join(parseErrors...)
}

func decodeEnvoyFilterDocument(configMap *corev1.ConfigMap, raw json.RawMessage) ([]model.GatewayPatch, error) {
	var document configSourceDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode Kubernetes object: %w", err)
	}
	if document.Kind == "List" {
		var result []model.GatewayPatch
		var parseErrors []error
		for index, item := range document.Items {
			filters, err := decodeEnvoyFilterDocument(configMap, item)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("list item %d: %w", index, err))
				continue
			}
			result = append(result, filters...)
		}
		return result, errors.Join(parseErrors...)
	}
	if document.Kind != "EnvoyFilter" || apiGroup(document.APIVersion) != envoyFilterAPIGroup {
		return nil, nil
	}
	if document.Metadata.Namespace == "" || document.Metadata.Name == "" {
		return nil, fmt.Errorf("EnvoyFilter metadata namespace and name are required")
	}
	if len(document.Spec) == 0 || string(document.Spec) == "null" {
		return nil, fmt.Errorf("EnvoyFilter %s/%s spec is required", document.Metadata.Namespace, document.Metadata.Name)
	}
	spec := &networking.EnvoyFilter{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(document.Spec, spec); err != nil {
		return nil, fmt.Errorf("decode EnvoyFilter %s/%s spec: %w",
			document.Metadata.Namespace, document.Metadata.Name, err)
	}
	policy, err := convertIstioEnvoyFilter(patchSourceMetadata{
		Namespace:       document.Metadata.Namespace,
		Name:            document.Metadata.Name,
		Source:          configMap.Namespace + "/" + configMap.Name,
		ResourceVersion: configMap.ResourceVersion,
		CreationTime:    document.Metadata.CreationTimestamp.Time,
	}, spec)
	if err != nil {
		return nil, fmt.Errorf("convert EnvoyFilter %s/%s: %w", document.Metadata.Namespace, document.Metadata.Name, err)
	}
	if policy == nil {
		return nil, nil
	}
	return []model.GatewayPatch{*policy}, nil
}

func apiGroup(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}
