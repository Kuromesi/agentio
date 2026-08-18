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
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	networkwasm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/wasm/v3"
	wasmextensions "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	networking "istio.io/api/networking/v1alpha3"
	api "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/util/protomarshal"
)

const (
	// SniPolicyTerminationClusterName is the internal cluster selected for TLS termination.
	SniPolicyTerminationClusterName = "agentio-sni-tls-termination"
	// SniPolicyPassthroughClusterName is the original-destination cluster selected for passthrough.
	SniPolicyPassthroughClusterName = util.PassthroughCluster

	SniPolicyWasmExtensionName = "networking.agents.kruise.io/sni-policy-wasm"
	sniPolicyWasmEnvoyFilter   = "agentio-internal-sni-policy-wasm"
	sniPolicyWasmRootID        = "agentio-sni-policy"
	sniPolicyWasmRuntime       = "envoy.wasm.runtime.v8"
)

func registerSniPolicyWasmExtension(store model.ConfigStore, rootNamespace, image string) error {
	extensionConfig, err := buildSniPolicyWasmEnvoyFilter(rootNamespace, image)
	if err != nil {
		return fmt.Errorf("build SNI traffic policy Wasm extension: %w", err)
	}
	if _, err := store.Create(extensionConfig); err != nil {
		return fmt.Errorf("register SNI traffic policy Wasm extension: %w", err)
	}
	return nil
}

// buildSniPolicyWasmEnvoyFilter creates an in-memory EnvoyFilter that only
// publishes the SNI Wasm through ECDS. The listener remains responsible for
// inserting that extension at the exact policy-enforcement point.
func buildSniPolicyWasmEnvoyFilter(rootNamespace, image string) (config.Config, error) {
	image, err := normalizeSniPolicyWasmImage(image)
	if err != nil {
		return config.Config{}, err
	}
	routeConfig, err := json.Marshal(map[string]string{
		"termination_cluster": SniPolicyTerminationClusterName,
		"passthrough_cluster": SniPolicyPassthroughClusterName,
	})
	if err != nil {
		return config.Config{}, fmt.Errorf("encode SNI Wasm route config: %w", err)
	}

	wasmConfig := &networkwasm.Wasm{Config: &wasmextensions.PluginConfig{
		Name:          sniPolicyWasmRootID,
		RootId:        sniPolicyWasmRootID,
		FailurePolicy: wasmextensions.FailurePolicy_FAIL_CLOSED,
		Configuration: protoconv.MessageToAny(&wrapperspb.StringValue{Value: string(routeConfig)}),
		Vm: &wasmextensions.PluginConfig_VmConfig{VmConfig: &wasmextensions.VmConfig{
			Runtime: sniPolicyWasmRuntime,
			Code: &core.AsyncDataSource{Specifier: &core.AsyncDataSource_Remote{Remote: &core.RemoteDataSource{
				HttpUri: &core.HttpUri{
					Uri:     image,
					Timeout: durationpb.New(30 * time.Second),
					HttpUpstreamType: &core.HttpUri_Cluster{
						Cluster: "_",
					},
				},
			}}},
			EnvironmentVariables: &wasmextensions.EnvironmentVariables{KeyValues: map[string]string{
				model.WasmResourceVersionEnv: image,
			}},
		}},
	}}
	typedExtension := &core.TypedExtensionConfig{
		Name:        SniPolicyWasmExtensionName,
		TypedConfig: protoconv.MessageToAny(wasmConfig),
	}
	patchValue, err := protomarshal.MessageToStructSlow(typedExtension)
	if err != nil {
		return config.Config{}, fmt.Errorf("encode SNI Wasm extension config: %w", err)
	}

	return config.Config{
		Meta: config.Meta{
			GroupVersionKind: gvk.EnvoyFilter,
			Name:             sniPolicyWasmEnvoyFilter,
			Namespace:        rootNamespace,
		},
		Spec: &networking.EnvoyFilter{
			TargetRefs: []*api.PolicyTargetReference{{
				Group: "gateway.networking.k8s.io",
				Kind:  "GatewayClass",
				Name:  constants.WaypointGatewayClassName,
			}},
			ConfigPatches: []*networking.EnvoyFilter_EnvoyConfigObjectPatch{{
				ApplyTo: networking.EnvoyFilter_EXTENSION_CONFIG,
				Patch: &networking.EnvoyFilter_Patch{
					Operation: networking.EnvoyFilter_Patch_ADD,
					Value:     patchValue,
				},
			}},
		},
	}, nil
}

func normalizeSniPolicyWasmImage(image string) (string, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", fmt.Errorf("SNI_TRAFFIC_POLICY_WASM_IMAGE is empty")
	}
	if !strings.Contains(image, "://") {
		image = "oci://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parse SNI_TRAFFIC_POLICY_WASM_IMAGE: %w", err)
	}
	switch parsed.Scheme {
	case "oci", "http", "https":
		return parsed.String(), nil
	default:
		return "", fmt.Errorf("unsupported SNI traffic policy Wasm image scheme %q", parsed.Scheme)
	}
}
