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

package model

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/config/schema/kubetypes"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/util/sets"
)

type SandboxConfig struct {
	*extensions.SandboxConfig
}

func (c SandboxConfig) ResourceName() string {
	return "sandbox-config"
}

func (m SandboxConfig) Equals(other SandboxConfig) bool {
	return proto.Equal(m.SandboxConfig, other.SandboxConfig)
}

func DefaultSandboxControllerConfig() *SandboxConfig {
	return &SandboxConfig{
		SandboxConfig: &extensions.SandboxConfig{
			SandboxIgnoredLabels: []string{
				"sidecar.istio.io/inject",
				"networking.agents.kruise.io/proxy-type",
				"security.istio.io/tlsMode",
				"networking.istio.io/tunnel",
				"istio.io/dataplane-mode",
				"pod-template-hash",
				"service.istio.io/canonical-name",
				"service.istio.io/canonical-revision",
				"pod-template-generation",
				"controller-revision-hash",
			},
		},
	}
}

// MakeSource is a helper to turn an Object into a model.TypedObject.
func MakeSource(o controllers.Object) TypedObject {
	return TypedObject{
		NamespacedName: config.NamespacedName(o),
		Kind:           gvk.MustToKind(kubetypes.GvkFromObject(o)),
	}
}

type WorkloadConfig struct {
	Name      string
	Namespace string
	Extension *extensions.WorkloadConfig
}

func (w WorkloadConfig) ResourceName() string {
	return fmt.Sprintf("%s/%s", w.Namespace, w.Name)
}

func (w WorkloadConfig) Equals(other WorkloadConfig) bool {
	return w.Namespace == other.Namespace && w.Name == other.Name && proto.Equal(w.Extension, other.Extension)
}

func (w WorkloadConfig) ConfigKey() ConfigKey {
	return ConfigKey{Kind: kind.WorkloadConfig, Name: w.Name, Namespace: w.Namespace}
}

func (sc *SandboxConfig) ExtractMatchHosts() sets.String {
	hosts := sets.New[string]()
	if sc == nil {
		return hosts
	}
	for _, p := range sc.GetEgressPolicies() {
		for _, h := range p.GetMatchHosts() {
			hosts.Insert(h)
		}
	}
	return hosts
}
