//go:build integ

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

package snipolicy

import (
	"fmt"
	"testing"

	"istio.io/api/label"
	controlleragentio "istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/test/framework"
	agentiocomp "istio.io/istio/pkg/test/framework/components/agentio"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
)

const (
	agentioConfigMapName = "agentio-config-primary"
	policyLabelKey       = "sni-policy-test"
)

var (
	i          istio.Instance
	ai         agentiocomp.Instance
	localNS    namespace.Instance
	globalNS   namespace.Instance
	selected   echo.Instance
	unselected echo.Instance
	global     echo.Instance
)

var (
	ambientMode = env.Register("AMBIENT_MODE", false,
		"Whether to use ambient mode (node-level ztunnel) instead of sidecar ztunnel").Get()
	firewallBackend = env.Register("FIREWALL_BACKEND", "auto",
		"Ztunnel firewall backend: auto or iptables").Get()
	enableFirewall = env.Register("ENABLE_FIREWALL", false,
		"Whether to enable firewall rules").Get()
	wasmImage = env.Register("AGENTIO_E2E_SNI_POLICY_WASM_IMAGE", "",
		"OCI image used by the SNI traffic policy network Wasm filter").Get()
	wasmInsecureRegistries = env.Register("AGENTIO_E2E_SNI_POLICY_WASM_INSECURE_REGISTRIES", "",
		"Comma-separated insecure registries allowed when fetching the SNI policy Wasm image").Get()
)

func TestMain(m *testing.M) {
	localNSConfig := namespace.Config{Prefix: "sni-policy", Inject: !ambientMode}
	globalNSConfig := namespace.Config{Prefix: "sni-policy-global", Inject: !ambientMode}
	if ambientMode {
		localNSConfig.Inject = false
		localNSConfig.Labels = map[string]string{label.IoIstioDataplaneMode.Name: "ambient"}
		globalNSConfig.Inject = false
		globalNSConfig.Labels = map[string]string{label.IoIstioDataplaneMode.Name: "ambient"}
	}

	suite := framework.NewSuite(m)
	if ambientMode {
		suite = suite.Setup(func(ctx resource.Context) error {
			ctx.Settings().Ambient = true
			return nil
		})
	}
	suite.
		Setup(func(resource.Context) error {
			if wasmImage == "" {
				return fmt.Errorf("AGENTIO_E2E_SNI_POLICY_WASM_IMAGE must be set for the SNI policy E2E suite")
			}
			return nil
		}).
		Setup(istio.Setup(&i, func(_ resource.Context, cfg *istio.Config) {
			cfg.DeployIstio = false
			cfg.SystemNamespace = agentiocomp.DefaultNamespace
		})).
		Setup(agentiocomp.Setup(&ai, func(_ resource.Context, cfg *agentiocomp.Config) {
			cfg.Values = map[string]string{
				"ambient.enabled":                         fmt.Sprintf("%t", ambientMode),
				"ambient.ztunnel.env.FIREWALL_BACKEND":    firewallBackend,
				"sidecarInjector.ztunnel.firewallBackend": firewallBackend,
				"global.enableFirewallRules":              fmt.Sprintf("%t", enableFirewall),
				"agentiod.resources.requests.cpu":         "1",
				"agentiod.resources.requests.memory":      "1Gi",
				"agentiod.resources.limits.cpu":           "1",
				"agentiod.resources.limits.memory":        "1Gi",
				"egressGateway.gateways[0].name":          "egress-gateway",
				"egressGateway.autoscaling.enabled":       "false",
				"egressGateway.replicas":                  "1",
				"egressGateway.resources.requests.cpu":    "100m",
				"egressGateway.resources.requests.memory": "128Mi",
				"egressGateway.resources.limits.cpu":      "1",
				"egressGateway.resources.limits.memory":   "512Mi",
				"sniTrafficPolicy.enabled":                "true",
				"sniTrafficPolicy.wasm.image":             wasmImage,
			}
			if wasmInsecureRegistries != "" {
				cfg.Values["egressGateway.env.WASM_INSECURE_REGISTRIES"] = wasmInsecureRegistries
			}
		})).
		Setup(namespace.Setup(&localNS, localNSConfig)).
		Setup(namespace.Setup(&globalNS, globalNSConfig)).
		Setup(deployClients).
		Setup(configureEgress).
		Run()
}

func deployClients(ctx resource.Context) error {
	annotations := map[string]string{}
	proxyLabels := map[string]string{}
	if !ambientMode {
		annotations["inject.istio.io/templates"] = "ztunnel"
		proxyLabels[controlleragentio.LabelSandboxProxyType] = "ztunnel"
	}

	_, err := deployment.New(ctx).
		With(&selected, echo.Config{
			Service:        "selected",
			Namespace:      localNS,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      mergedLabels(proxyLabels, policyLabelKey, "selected"),
			}},
			Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		}).
		With(&unselected, echo.Config{
			Service:        "unselected",
			Namespace:      localNS,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      mergedLabels(proxyLabels, policyLabelKey, "unselected"),
			}},
			Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		}).
		With(&global, echo.Config{
			Service:        "global",
			Namespace:      globalNS,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      mergedLabels(proxyLabels, policyLabelKey, "global"),
			}},
			Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		}).
		Build()
	return err
}

func mergedLabels(base map[string]string, key, value string) map[string]string {
	result := make(map[string]string, len(base)+1)
	for k, v := range base {
		result[k] = v
	}
	result[key] = value
	return result
}

func configureEgress(ctx resource.Context) error {
	return ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
		"Namespace": i.Settings().SystemNamespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        # includeHosts remains the authorization boundary for on-demand SDS.
        # SecurityProfiles decide which matching workloads actually terminate.
        includeHosts:
        - "example.com"
        excludeHosts:
        - "example.net"
`).Apply()
}
