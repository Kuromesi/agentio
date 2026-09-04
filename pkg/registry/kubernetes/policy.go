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
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	legacyproto "github.com/golang/protobuf/proto" //nolint:staticcheck // jsonpb accepts the legacy message adapter.
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	baseConfigMapName    = "agentio-config"
	primaryConfigMapName = "agentio-config-primary"
	agentioConfigKey     = "config"
)

// AgentioConfigMapOptions identifies the ordered Kubernetes sources for
// Agentio configuration. PrimaryName may be empty to disable the overlay.
type AgentioConfigMapOptions struct {
	BaseName    string
	PrimaryName string
}

func defaultAgentioConfigMapOptions() AgentioConfigMapOptions {
	return AgentioConfigMapOptions{
		BaseName:    baseConfigMapName,
		PrimaryName: primaryConfigMapName,
	}
}

func defaultAgentioConfiguration() *configv1.AgentioConfig {
	return &configv1.AgentioConfig{
		SandboxIgnoredLabels: []string{
			"agentio.kruise.io/dataplane-mode",
			"pod-template-hash",
			"pod-template-generation",
			"controller-revision-hash",
		},
	}
}

// effectiveAgentioConfiguration merges defaults, the base ConfigMap, then the primary ConfigMap; parse failures discard the update (last known good).
func effectiveAgentioConfiguration(
	ctx krt.HandlerContext,
	configMaps krt.Collection[*corev1.ConfigMap],
	rootNamespace string,
	configMapOptions AgentioConfigMapOptions,
) *model.AgentioConfiguration {
	value := defaultAgentioConfiguration()
	resourceVersions := make([]string, 0, 2)
	for _, name := range []string{configMapOptions.BaseName, configMapOptions.PrimaryName} {
		if name == "" {
			continue
		}
		configMap := krt.FetchOne(ctx, configMaps, krt.FilterKey(rootNamespace+"/"+name))
		if configMap == nil {
			continue
		}
		resourceVersions = append(resourceVersions, name+"="+(*configMap).ResourceVersion)
		content := (*configMap).Data[agentioConfigKey]
		if strings.TrimSpace(content) == "" {
			continue
		}
		applied, err := applyAgentioConfig(content, value)
		if err != nil {
			log.Warn("retain last-known-good Agentio configuration",
				"configmap", name, "error", err)
			ctx.DiscardResult()
			return nil
		}
		value = applied
	}
	return &model.AgentioConfiguration{
		Value:           value,
		ResourceVersion: strings.Join(resourceVersions, ","),
	}
}

// applyAgentioConfig overlays YAML onto base using jsonpb merge semantics.
func applyAgentioConfig(content string, base *configv1.AgentioConfig) (*configv1.AgentioConfig, error) {
	value := &configv1.AgentioConfig{}
	if base != nil {
		value = proto.Clone(base).(*configv1.AgentioConfig)
	}
	if err := decodeAgentioYAML(content, "effective Agentio configuration", legacyproto.MessageV1(value)); err != nil {
		return nil, err
	}
	if err := normalizeEgressServiceEntries(value.GetEgressGateways()); err != nil {
		return nil, err
	}
	return value, nil
}
