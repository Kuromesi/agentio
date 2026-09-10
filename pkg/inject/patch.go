// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package inject

import (
	"encoding/json"
	"fmt"

	jsonpatch "gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"sigs.k8s.io/yaml"
)

func createPatch(pod *corev1.Pod, original []byte) ([]byte, error) {
	reinjected, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	p, err := jsonpatch.CreatePatch(original, reinjected)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// applyContainer merges a container spec on top of the provided pod
func applyContainer(target *corev1.Pod, container corev1.Container) (*corev1.Pod, error) {
	overlay := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}

	overlayJSON, err := json.Marshal(overlay)
	if err != nil {
		return nil, err
	}

	return applyOverlay(target, overlayJSON)
}

// applyInitContainer merges a container spec on top of the provided pod as an init container
func applyInitContainer(target *corev1.Pod, container corev1.Container) (*corev1.Pod, error) {
	overlay := &corev1.Pod{Spec: corev1.PodSpec{
		// We need to set containers to empty, otherwise it will marshal as "null" and delete all containers
		Containers:     []corev1.Container{},
		InitContainers: []corev1.Container{container},
	}}

	overlayJSON, err := json.Marshal(overlay)
	if err != nil {
		return nil, err
	}

	return applyOverlay(target, overlayJSON)
}

func patchHandleUnmarshal(j []byte, unmarshal func(data []byte, v any) error) (map[string]any, error) {
	if j == nil {
		j = []byte("{}")
	}

	m := map[string]any{}
	err := unmarshal(j, &m)
	if err != nil {
		return nil, mergepatch.ErrBadJSONDoc
	}
	return m, nil
}

// StrategicMergePatchYAML is a small fork of strategicpatch.StrategicMergePatch to allow YAML patches
// This avoids expensive conversion from YAML to JSON
func StrategicMergePatchYAML(originalJSON []byte, patchYAML []byte, dataStruct any) ([]byte, error) {
	schema, err := strategicpatch.NewPatchMetaFromStruct(dataStruct)
	if err != nil {
		return nil, err
	}

	originalMap, err := patchHandleUnmarshal(originalJSON, json.Unmarshal)
	if err != nil {
		return nil, err
	}
	patchMap, err := patchHandleUnmarshal(patchYAML, func(data []byte, v any) error {
		return yaml.Unmarshal(data, v)
	})
	if err != nil {
		return nil, err
	}

	result, err := strategicpatch.StrategicMergeMapPatchUsingLookupPatchMeta(originalMap, patchMap, schema)
	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

// applyOverlayYAML merges a pod spec, provided as YAML, on top of the provided pod
func applyOverlayYAML(target *corev1.Pod, overlayYAML []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := StrategicMergePatchYAML(currentJSON, overlayYAML, pod)
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %w", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %w", err)
	}
	return &pod, nil
}

// applyOverlay merges a pod spec, provided as JSON, on top of the provided pod
func applyOverlay(target *corev1.Pod, overlayJSON []byte) (*corev1.Pod, error) {
	currentJSON, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}

	pod := corev1.Pod{}
	// Overlay the injected template onto the original podSpec
	patched, err := strategicpatch.StrategicMergePatch(currentJSON, overlayJSON, pod)
	if err != nil {
		return nil, fmt.Errorf("strategic merge: %w", err)
	}

	if err := json.Unmarshal(patched, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal patched pod: %w", err)
	}
	return &pod, nil
}

const (
	// AutoImage means the injected image wins; container.image is required,
	// so customizers must set some image.
	AutoImage = "auto"
)
