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

package trafficpolicy

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

func trafficPolicy(name, namespace string, selector map[string]string, action, cidr string) *unstructured.Unstructured {
	matchLabels := make(map[string]any, len(selector))
	for key, value := range selector {
		matchLabels[key] = value
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       "TrafficPolicy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"priority": int64(100),
			"selector": map[string]any{
				"matchLabels": matchLabels,
			},
			"egress": map[string]any{
				"rules": []any{
					map[string]any{
						"action": action,
						"to": []any{
							map[string]any{"cidr": cidr},
						},
					},
					map[string]any{
						"action": "allow",
						"to": []any{
							map[string]any{"cidr": "0.0.0.0/0"},
						},
					},
				},
			},
		},
	}}
}
