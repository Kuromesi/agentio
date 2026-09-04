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

package kube

import (
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func DecodeYAML(reader io.Reader) ([]*unstructured.Unstructured, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(reader, 4096)
	var objects []*unstructured.Unstructured
	for document := 1; ; document++ {
		var raw any
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				return objects, nil
			}
			return nil, fmt.Errorf("decode YAML document %d: %w", document, err)
		}
		if raw == nil {
			continue
		}
		content, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decode YAML document %d: expected a Kubernetes object, got %T", document, raw)
		}
		if len(content) == 0 {
			continue
		}
		object := &unstructured.Unstructured{Object: content}
		if object.IsList() {
			list, err := object.ToList()
			if err != nil {
				return nil, fmt.Errorf("decode YAML document %d list: %w", document, err)
			}
			for i := range list.Items {
				objects = append(objects, list.Items[i].DeepCopy())
			}
			continue
		}
		objects = append(objects, object)
	}
}
