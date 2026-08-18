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
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	networkwasm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/wasm/v3"
	wasmextensions "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	"google.golang.org/protobuf/types/known/structpb"

	networking "istio.io/api/networking/v1alpha3"
	xdsconfig "istio.io/istio/pkg/config/xds"
)

func TestBuildSniPolicyWasmEnvoyFilter(t *testing.T) {
	cfg, err := buildSniPolicyWasmEnvoyFilter("istio-system", "registry.example.com/agentio/sni-policy:v1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Namespace != "istio-system" {
		t.Fatalf("EnvoyFilter namespace = %q, want istio-system", cfg.Namespace)
	}
	patches := cfg.Spec.(*networking.EnvoyFilter).GetConfigPatches()
	if len(patches) != 1 || patches[0].GetApplyTo() != networking.EnvoyFilter_EXTENSION_CONFIG ||
		patches[0].GetPatch().GetOperation() != networking.EnvoyFilter_Patch_ADD {
		t.Fatalf("unexpected SNI Wasm EnvoyFilter patches: %v", patches)
	}
	resource, err := xdsconfig.BuildXDSObjectFromStruct(
		networking.EnvoyFilter_EXTENSION_CONFIG,
		patches[0].GetPatch().GetValue(),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	extensionConfig := resource.(*core.TypedExtensionConfig)
	if extensionConfig.GetName() != SniPolicyWasmExtensionName {
		t.Fatalf("extension name = %q, want %q", extensionConfig.GetName(), SniPolicyWasmExtensionName)
	}
	wasmConfig := &networkwasm.Wasm{}
	if err := extensionConfig.GetTypedConfig().UnmarshalTo(wasmConfig); err != nil {
		t.Fatal(err)
	}
	if got, want := wasmConfig.GetConfig().GetVmConfig().GetCode().GetRemote().GetHttpUri().GetUri(),
		"oci://registry.example.com/agentio/sni-policy:v1"; got != want {
		t.Fatalf("Wasm image = %q, want %q", got, want)
	}
	if got := wasmConfig.GetConfig().GetFailurePolicy(); got != wasmextensions.FailurePolicy_FAIL_CLOSED {
		t.Fatalf("failure policy = %v, want FAIL_CLOSED", got)
	}
	pluginConfig := &structpb.Struct{}
	if err := wasmConfig.GetConfig().GetConfiguration().UnmarshalTo(pluginConfig); err != nil {
		t.Fatal(err)
	}
	if got, want := pluginConfig.GetFields()["termination_cluster"].GetStringValue(), SniPolicyTerminationClusterName; got != want {
		t.Fatalf("termination cluster = %q, want %q", got, want)
	}
	if got, want := pluginConfig.GetFields()["passthrough_cluster"].GetStringValue(), SniPolicyPassthroughClusterName; got != want {
		t.Fatalf("passthrough cluster = %q, want %q", got, want)
	}
}

func TestNormalizeSniPolicyWasmImage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "implicit OCI", input: "registry.example.com/agentio/sni-policy:v1", want: "oci://registry.example.com/agentio/sni-policy:v1"},
		{name: "explicit OCI", input: "oci://registry.example.com/agentio/sni-policy:v1", want: "oci://registry.example.com/agentio/sni-policy:v1"},
		{name: "HTTPS", input: "https://example.com/sni-policy.wasm", want: "https://example.com/sni-policy.wasm"},
		{name: "empty", wantErr: true},
		{name: "unsupported", input: "file:///plugin.wasm", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSniPolicyWasmImage(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("normalizeSniPolicyWasmImage(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("normalizeSniPolicyWasmImage(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
