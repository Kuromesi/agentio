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

package agentio

import (
	"fmt"
	"path"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/util/protomarshal"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
)

const AgentioConfigMapKey = "config"

var (
	AgentioConfigMapName = env.Register("AGENTIO_CONFIGMAP_NAME", "agentio-config",
		"ConfigMap name of agentio config").Get()
	PrimaryAgentioConfigMapName = env.Register("PRIMARY_AGENTIO_CONFIGMAP_NAME", "agentio-config-primary",
		"ConfigMap name of primary sandbox config. When set, this config takes precedence over the base agentio config.").Get()
)

func IgnoreSandboxLabels(labels map[string]string, sandboxIgnoredLabels []string) map[string]string {
	cloned := make(map[string]string)
	for k, v := range labels {
		if !matchesIgnoredLabel(k, sandboxIgnoredLabels) {
			cloned[k] = v
		}
	}
	return cloned
}

func matchesIgnoredLabel(key string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == key {
			return true
		}
		if matched, _ := path.Match(pattern, key); matched {
			return true
		}
	}
	return false
}

func applyAgentioConfig(yml string, defaultConfig *model.AgentioConfig) (*model.AgentioConfig, error) {
	out := &model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{}}
	if defaultConfig != nil && defaultConfig.AgentioConfig != nil {
		out.AgentioConfig = proto.Clone(defaultConfig.AgentioConfig).(*extensions.AgentioConfig)
	}
	if err := protomarshal.ApplyYAML(yml, out.AgentioConfig); err != nil {
		return nil, err
	}
	log.Infof("Loaded sandbox config: %v", out.AgentioConfig)
	return out, nil
}

func newAgentioConfig(client kube.Client, rootNamespace string, opts krt.OptionsBuilder) krt.Singleton[model.AgentioConfig] {
	clt := kclient.NewFiltered[*v1.ConfigMap](client, kclient.Filter{
		Namespace:     rootNamespace,
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, AgentioConfigMapName).String(),
	})
	cms := krt.WrapClient(clt, opts.WithName("ConfigMap_"+AgentioConfigMapName)...)
	clt.Start(opts.Stop())

	var primaryCms krt.Collection[*v1.ConfigMap]
	var primaryCmKey string
	if PrimaryAgentioConfigMapName != "" {
		primaryClt := kclient.NewFiltered[*v1.ConfigMap](client, kclient.Filter{
			Namespace:     rootNamespace,
			FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, PrimaryAgentioConfigMapName).String(),
		})
		primaryCms = krt.WrapClient(primaryClt, opts.WithName("ConfigMap_"+PrimaryAgentioConfigMapName)...)
		primaryClt.Start(opts.Stop())
		primaryCmKey = types.NamespacedName{Namespace: rootNamespace, Name: PrimaryAgentioConfigMapName}.String()
	}

	cmKey := types.NamespacedName{Namespace: rootNamespace, Name: AgentioConfigMapName}.String()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *model.AgentioConfig {
		cfg := model.DefaultAgentioConfig()

		// Apply base config (Helm-managed)
		if cm := ptr.Flatten(krt.FetchOne(ctx, cms, krt.FilterKey(cmKey))); cm != nil {
			if cfgYaml, exists := cm.Data[AgentioConfigMapKey]; exists {
				applied, err := applyAgentioConfig(cfgYaml, cfg)
				if err != nil {
					log.Warnf("Failed to apply base sandbox config, err: %+v", err)
				} else {
					cfg = applied
				}
			}
		}

		// Apply primary config (user-managed, higher priority)
		if primaryCms != nil {
			if cm := ptr.Flatten(krt.FetchOne(ctx, primaryCms, krt.FilterKey(primaryCmKey))); cm != nil {
				if cfgYaml, exists := cm.Data[AgentioConfigMapKey]; exists {
					applied, err := applyAgentioConfig(cfgYaml, cfg)
					if err != nil {
						log.Warnf("Failed to apply primary sandbox config, err: %+v", err)
					} else {
						cfg = applied
					}
				}
			}
		}

		return cfg
	}, opts.WithName(fmt.Sprintf("ConfigMap_%s_%s", AgentioConfigMapName, AgentioConfigMapKey))...)
}
