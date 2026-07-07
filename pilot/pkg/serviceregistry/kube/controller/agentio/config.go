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

var (
	SandboxConfigMapName = env.Register("SANDBOX_CONFIGMAP_NAME", "sandbox-config",
		"ConfigMap name of sandbox config").Get()
	PrimarySandboxConfigMapName = env.Register("PRIMARY_SANDBOX_CONFIGMAP_NAME", "sandbox-config-primary",
		"ConfigMap name of primary sandbox config. When set, this config takes precedence over the base sandbox config.").Get()
	SandboxConfigMapKey = env.Register("SANDBOX_CONFIGMAP_KEY",
		"config", "Sandbox configmap key.").Get()
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

func applySandboxConfig(yml string, defaultConfig *model.SandboxConfig) (*model.SandboxConfig, error) {
	out := &model.SandboxConfig{SandboxConfig: &extensions.SandboxConfig{}}
	if defaultConfig != nil && defaultConfig.SandboxConfig != nil {
		out.SandboxConfig = proto.Clone(defaultConfig.SandboxConfig).(*extensions.SandboxConfig)
	}
	if err := protomarshal.ApplyYAML(yml, out.SandboxConfig); err != nil {
		return nil, err
	}
	log.Infof("Loaded sandbox config: %v", out.SandboxConfig)
	return out, nil
}

func newSandboxControllerConfig(client kube.Client, rootNamespace string, opts krt.OptionsBuilder) krt.Singleton[model.SandboxConfig] {
	clt := kclient.NewFiltered[*v1.ConfigMap](client, kclient.Filter{
		Namespace:     rootNamespace,
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, SandboxConfigMapName).String(),
	})
	cms := krt.WrapClient(clt, opts.WithName("ConfigMap_"+SandboxConfigMapName)...)
	clt.Start(opts.Stop())

	var primaryCms krt.Collection[*v1.ConfigMap]
	var primaryCmKey string
	if PrimarySandboxConfigMapName != "" {
		primaryClt := kclient.NewFiltered[*v1.ConfigMap](client, kclient.Filter{
			Namespace:     rootNamespace,
			FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, PrimarySandboxConfigMapName).String(),
		})
		primaryCms = krt.WrapClient(primaryClt, opts.WithName("ConfigMap_"+PrimarySandboxConfigMapName)...)
		primaryClt.Start(opts.Stop())
		primaryCmKey = types.NamespacedName{Namespace: rootNamespace, Name: PrimarySandboxConfigMapName}.String()
	}

	cmKey := types.NamespacedName{Namespace: rootNamespace, Name: SandboxConfigMapName}.String()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *model.SandboxConfig {
		cfg := model.DefaultSandboxControllerConfig()

		// Apply base config (Helm-managed)
		if cm := ptr.Flatten(krt.FetchOne(ctx, cms, krt.FilterKey(cmKey))); cm != nil {
			if cfgYaml, exists := cm.Data[SandboxConfigMapKey]; exists {
				applied, err := applySandboxConfig(cfgYaml, cfg)
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
				if cfgYaml, exists := cm.Data[SandboxConfigMapKey]; exists {
					applied, err := applySandboxConfig(cfgYaml, cfg)
					if err != nil {
						log.Warnf("Failed to apply primary sandbox config, err: %+v", err)
					} else {
						cfg = applied
					}
				}
			}
		}

		return cfg
	}, opts.WithName(fmt.Sprintf("ConfigMap_%s_%s", SandboxConfigMapName, SandboxConfigMapKey))...)
}
