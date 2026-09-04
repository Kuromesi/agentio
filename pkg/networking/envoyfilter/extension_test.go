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
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestApplyExtensionConfigurationsAddsGatewayScopedValues(t *testing.T) {
	filter, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: "ecds", Source: "source",
	}, 0, []string{"demo/gateway"}, []model.EnvoyPatch{{
		Operation: model.PatchAdd,
		Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{
			Name: "gateway-extension",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	patches := NewPatchSet([]model.GatewayPatch{filter})
	got, err := ApplyExtensionConfigurations(patches, []*corev3.TypedExtensionConfig{{Name: "existing"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GetName() != "existing" || got[1].GetName() != "gateway-extension" {
		t.Fatalf("extension configurations = %+v", got)
	}
}
