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

package agentio

import (
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/config/file"
	pilotmodel "istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/core/envoyfilter"
	serviceregistrymemory "istio.io/istio/pilot/pkg/serviceregistry/memory"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/test/util/tmpl"
	"istio.io/istio/pkg/test/util/yml"
)

func TestForwardHTTPConnectProxyEnvoyFilterConfiguration(t *testing.T) {
	const namespace = "agentio-system"
	rendered, err := tmpl.EvaluateFile("testdata/forward-http-connect-proxy.yaml", map[string]string{
		"EnvoyYAML":      "static_resources: {}",
		"Namespace":      namespace,
		"ProxyKey":       "proxy-key",
		"ProxyCertChain": "proxy-cert-chain",
		"ProxyCA":        "proxy-ca",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, document := range yml.SplitString(rendered) {
		configMap := corev1.ConfigMap{}
		if err := yaml.Unmarshal([]byte(document), &configMap); err != nil {
			t.Fatal(err)
		}
		if configMap.Name != "forward-http-connect-proxy-ca" {
			continue
		}

		var source struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				TargetRefs []struct {
					Group string `json:"group"`
					Kind  string `json:"kind"`
					Name  string `json:"name"`
				} `json:"targetRefs"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal([]byte(configMap.Data["sources"]), &source); err != nil {
			t.Fatal(err)
		}
		if source.Metadata.Namespace != namespace {
			t.Fatalf("embedded EnvoyFilter namespace = %q, want %q", source.Metadata.Namespace, namespace)
		}
		if len(source.Spec.TargetRefs) != 1 ||
			source.Spec.TargetRefs[0].Group != "gateway.networking.k8s.io" ||
			source.Spec.TargetRefs[0].Kind != "Gateway" ||
			source.Spec.TargetRefs[0].Name != "egress-gateway" {
			t.Fatalf("embedded EnvoyFilter targetRefs = %+v, want Gateway/egress-gateway", source.Spec.TargetRefs)
		}

		store := file.NewKubeSource(collections.PilotGatewayAPI())
		if err := store.ApplyContent("forward-http-connect-proxy-ca", configMap.Data["sources"]); err != nil {
			t.Fatal(err)
		}
		meshConfig := mesh.DefaultMeshConfig()
		meshConfig.RootNamespace = namespace
		environment := &pilotmodel.Environment{
			ConfigStore:      store,
			ServiceDiscovery: serviceregistrymemory.NewServiceDiscovery(),
			Watcher:          meshwatcher.NewTestWatcher(meshConfig),
		}
		environment.Init()
		push := pilotmodel.NewPushContext()
		push.InitContext(environment, nil, nil)
		proxy := &pilotmodel.Proxy{
			Type:            pilotmodel.Waypoint,
			ConfigNamespace: namespace,
			Labels: map[string]string{
				"gateway.networking.k8s.io/gateway-name": "egress-gateway",
			},
		}
		filters := push.EnvoyFilters(proxy)
		if filters == nil || len(filters.Patches[networking.EnvoyFilter_CLUSTER]) != 1 {
			t.Fatalf("embedded EnvoyFilter does not select the egress gateway waypoint")
		}
		patched := envoyfilter.ApplyClusterMerge(networking.EnvoyFilter_SIDECAR_OUTBOUND, filters, &cluster.Cluster{
			Name: "tls_proxy_originate",
		}, nil)
		if patched == nil || patched.GetTransportSocket() == nil {
			t.Fatal("embedded EnvoyFilter did not patch tls_proxy_originate")
		}
		upstreamTLS := &tls.UpstreamTlsContext{}
		if err := patched.GetTransportSocket().GetTypedConfig().UnmarshalTo(upstreamTLS); err != nil {
			t.Fatal(err)
		}
		if got := upstreamTLS.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetInlineString(); got != "proxy-ca" {
			t.Fatalf("patched trusted CA = %q, want proxy-ca", got)
		}
		return
	}

	t.Fatal("forward-http-connect-proxy-ca ConfigMap not found")
}
