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

package envoyfilter

import (
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func ApplyExtensionConfigurations(
	patches *Patches,
	input []*corev3.TypedExtensionConfig,
) ([]*corev3.TypedExtensionConfig, error) {
	result := make([]*corev3.TypedExtensionConfig, 0, len(input))
	for _, configuration := range input {
		if configuration != nil {
			result = append(result, proto.Clone(configuration).(*corev3.TypedExtensionConfig))
		}
	}
	for _, patch := range patches.For(extensionConfigurationTarget) {
		if patch.Operation != model.PatchAdd {
			continue
		}
		value := patch.extensionConfiguration().Value
		result = append(result, proto.Clone(value).(*corev3.TypedExtensionConfig))
	}
	seen := sets.NewWithLength[string](len(result))
	for _, configuration := range result {
		if configuration.GetName() == "" {
			return nil, fmt.Errorf("EnvoyFilter produced an extension configuration with an empty name")
		}
		if seen.Contains(configuration.GetName()) {
			return nil, fmt.Errorf("EnvoyFilter produced duplicate extension configuration %q", configuration.GetName())
		}
		seen.Insert(configuration.GetName())
	}
	return result, nil
}
