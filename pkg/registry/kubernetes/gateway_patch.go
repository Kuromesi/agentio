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
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func newGatewayPatchesCollection(
	configMaps krt.Collection[*corev1.ConfigMap],
	rootNamespace string,
	options ...krt.CollectionOption,
) krt.Collection[model.GatewayPatch] {
	return krt.NewManyCollection(configMaps, func(ctx krt.HandlerContext, configMap *corev1.ConfigMap) []model.GatewayPatch {
		if configMap.Namespace != rootNamespace {
			return nil
		}
		patches, err := decodeGatewayPatches(configMap)
		if err != nil {
			log.Warn("retain last-known-good gateway patches", "namespace", configMap.Namespace,
				"configmap", configMap.Name, "resourceVersion", configMap.ResourceVersion, "error", err)
			ctx.DiscardResult()
			return nil
		}
		return patches
	}, options...)
}

func decodeGatewayPatches(configMap *corev1.ConfigMap) ([]model.GatewayPatch, error) {
	if configMap == nil {
		return nil, nil
	}
	// The gateway-patch type label selects data.patches, including empty data.
	// Parse errors must not cause a fallback to data.sources.
	if configMap.Labels[ManifestTypeConfigMapLabel] == GatewayPatchManifestType {
		patch, err := decodePatchConfig(configMap)
		if err != nil {
			return nil, fmt.Errorf("data.%s: %w", KubePatchDataKey, err)
		}
		if patch == nil {
			return nil, nil
		}
		return []model.GatewayPatch{*patch}, nil
	}
	patches, err := decodeEnvoyFilters(configMap)
	if err != nil {
		return nil, fmt.Errorf("data.%s: %w", KubeSourceDataKey, err)
	}
	return patches, nil
}
