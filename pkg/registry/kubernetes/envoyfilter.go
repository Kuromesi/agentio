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
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	networking "istio.io/api/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	KubeSourceConfigMapLabel = "manifests.agents.kruise.io/kube-source"
	KubeSourceDataKey        = "sources"
	envoyFilterAPIGroup      = "networking.istio.io"
)

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
	return decodeConfigSources(configMap, "EnvoyFilter", decodeEnvoyFilterDocument)
}

func decodeEnvoyFilterDocument(configMap *corev1.ConfigMap, raw json.RawMessage) ([]model.GatewayPatch, error) {
	return decodeConfigSourceDocument(configMap, raw, "EnvoyFilter", envoyFilterAPIGroup, convertEnvoyFilterDocument)
}

func convertEnvoyFilterDocument(configMap *corev1.ConfigMap, document configSourceDocument) ([]model.GatewayPatch, error) {
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
