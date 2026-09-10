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

	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
)

type configSourceDocument struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       json.RawMessage   `json:"spec"`
	Items      []json.RawMessage `json:"items"`
}

// decodeConfigSources preserves document order and aggregates errors. Callers
// discard the entire result on error to retain their last-known-good collection.
func decodeConfigSources[T interface{ LogicalName() string }](configMap *corev1.ConfigMap, kind string, decode func(*corev1.ConfigMap, json.RawMessage) ([]T, error)) ([]T, error) {
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
	var result []T
	var parseErrors []error
	seen := sets.New[string]()
	for document := 0; ; document++ {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			parseErrors = append(parseErrors, fmt.Errorf("decode document %d: %w", document, err))
			break
		}
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		objects, err := decode(configMap, raw)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("document %d: %w", document, err))
			continue
		}
		for _, object := range objects {
			name := object.LogicalName()
			if seen.Contains(name) {
				parseErrors = append(parseErrors, fmt.Errorf("duplicate %s %s in one ConfigMap", kind, name))
				continue
			}
			seen.Insert(name)
			result = append(result, object)
		}
	}
	return result, errors.Join(parseErrors...)
}

func decodeConfigSourceDocument[T any](configMap *corev1.ConfigMap, raw json.RawMessage, kind, group string, convert func(*corev1.ConfigMap, configSourceDocument) ([]T, error)) ([]T, error) {
	var document configSourceDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode Kubernetes object: %w", err)
	}
	if document.Kind == "List" {
		var result []T
		var parseErrors []error
		for index, item := range document.Items {
			objects, err := decodeConfigSourceDocument(configMap, item, kind, group, convert)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("list item %d: %w", index, err))
				continue
			}
			result = append(result, objects...)
		}
		return result, errors.Join(parseErrors...)
	}
	if document.Kind != kind || apiGroup(document.APIVersion) != group {
		return nil, nil
	}
	if document.Metadata.Namespace == "" || document.Metadata.Name == "" {
		return nil, fmt.Errorf("%s metadata namespace and name are required", kind)
	}
	if len(document.Spec) == 0 || string(document.Spec) == "null" {
		return nil, fmt.Errorf("%s %s/%s spec is required", kind, document.Metadata.Namespace, document.Metadata.Name)
	}
	return convert(configMap, document)
}

func apiGroup(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}
