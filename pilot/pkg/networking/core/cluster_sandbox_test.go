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

package core

import (
	"slices"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	dfpcluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstream "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	agentio "istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/wellknown"
)

func TestSandboxClusters_RegistersPlaintextHTTPDynamicForwardProxy(t *testing.T) {
	cb := &ClusterBuilder{req: &model.PushRequest{Push: &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
	}}}

	var got *cluster.Cluster
	for _, c := range sandboxClusters(cb, nil) {
		if c.GetName() == "http_dynamic_forward_proxy" {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("plaintext HTTP dynamic forward proxy cluster is not registered")
	}
	if got.GetTransportSocket() != nil {
		t.Fatal("plaintext HTTP dynamic forward proxy must not originate TLS")
	}
	if got.GetClusterType().GetName() != "envoy.clusters.dynamic_forward_proxy" {
		t.Fatalf("cluster type = %q, want dynamic forward proxy", got.GetClusterType().GetName())
	}

	dfpConfig := &dfpcluster.ClusterConfig{}
	if err := got.GetClusterType().GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
		t.Fatalf("decode dynamic forward proxy cluster: %v", err)
	}
	if !dfpConfig.GetAllowInsecureClusterOptions() {
		t.Fatal("plaintext HTTP dynamic forward proxy must allow cluster options without TLS validation")
	}
	if got, want := dfpConfig.GetDnsCacheConfig().GetName(), "agentio_dns_cache"; got != want {
		t.Fatalf("DNS cache = %q, want %q", got, want)
	}
}

func TestSandboxClusters_TLSOriginationRequiresSecureClusterOptions(t *testing.T) {
	cb := &ClusterBuilder{req: &model.PushRequest{Push: &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
	}}}

	var got *cluster.Cluster
	for _, c := range sandboxClusters(cb, nil) {
		if c.GetName() == "tls_connect_originate" {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("TLS-origination dynamic forward proxy cluster is not registered")
	}

	dfpConfig := &dfpcluster.ClusterConfig{}
	if err := got.GetClusterType().GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
		t.Fatalf("decode dynamic forward proxy cluster: %v", err)
	}
	if dfpConfig.GetAllowInsecureClusterOptions() {
		t.Fatal("TLS-origination dynamic forward proxy must require secure cluster options")
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := got.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode upstream TLS context: %v", err)
	}
	assertSandboxUpstreamTLSParameters(t, tlsContext.GetCommonTlsContext().GetTlsParams())
	// An absent wrapper enables Envoy's default session cache; require explicit zero.
	if keys := tlsContext.GetMaxSessionKeys(); keys == nil || keys.GetValue() != 0 {
		t.Fatalf("max session keys = %v, want explicit zero to prevent cross-SNI session reuse", keys)
	}
	if got, want := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(), security.GetOSRootFilePath(); got != want {
		t.Fatalf("trusted CA = %q, want OS roots %q", got, want)
	}
	httpOptions := &httpupstream.HttpProtocolOptions{}
	if err := got.GetTypedExtensionProtocolOptions()[v3.HttpProtocolOptionsType].UnmarshalTo(httpOptions); err != nil {
		t.Fatalf("decode HTTP protocol options: %v", err)
	}
	if !httpOptions.GetUpstreamHttpProtocolOptions().GetAutoSni() || !httpOptions.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
		t.Fatal("TLS origination must retain automatic SNI and SAN validation")
	}
}

func TestSandboxClusters_TargetRefEnvoyFilterPatchesTLSOrigination(t *testing.T) {
	const envoyFilter = `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: patch-sandbox-tls-ca
  namespace: istio-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: ANY
      cluster:
        name: tls_connect_originate
    patch:
      operation: MERGE
      value:
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            common_tls_context:
              validation_context:
                trusted_ca:
                  inline_string: test-ca
`

	cg := NewConfigGenTest(t, TestOptions{ConfigString: envoyFilter})
	proxy := sandboxEgressNode()
	proxy.Type = model.Waypoint
	proxy.Labels["gateway.networking.k8s.io/gateway-name"] = "egress-gateway"

	var got *cluster.Cluster
	for _, c := range cg.Clusters(cg.SetupProxy(proxy)) {
		if c.GetName() == tlsOriginateCluster {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("TLS-origination dynamic forward proxy cluster is not registered")
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := got.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode upstream TLS context: %v", err)
	}
	if got, want := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetInlineString(), "test-ca"; got != want {
		t.Fatalf("trusted CA inline string = %q, want EnvoyFilter value %q", got, want)
	}
}

func TestSandboxClusters_TLSProxyOriginationUsesOriginalDestination(t *testing.T) {
	cb := &ClusterBuilder{req: &model.PushRequest{Push: &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
	}}}

	var got *cluster.Cluster
	for _, c := range sandboxClusters(cb, nil) {
		if c.GetName() == "tls_proxy_originate" {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatal("TLS proxy original-destination cluster is not registered")
	}
	if got.GetType() != cluster.Cluster_ORIGINAL_DST {
		t.Fatalf("cluster type = %v, want ORIGINAL_DST", got.GetType())
	}
	if got.GetLbPolicy() != cluster.Cluster_CLUSTER_PROVIDED {
		t.Fatalf("load balancing policy = %v, want CLUSTER_PROVIDED", got.GetLbPolicy())
	}
	if got.GetTransportSocket().GetName() != wellknown.TransportSocketTLS {
		t.Fatalf("transport socket = %q, want %q", got.GetTransportSocket().GetName(), wellknown.TransportSocketTLS)
	}

	httpOptions := &httpupstream.HttpProtocolOptions{}
	if err := got.GetTypedExtensionProtocolOptions()[v3.HttpProtocolOptionsType].UnmarshalTo(httpOptions); err != nil {
		t.Fatalf("decode HTTP protocol options: %v", err)
	}
	if httpOptions.GetAutoConfig() == nil {
		t.Fatal("TLS proxy cluster must select its HTTP codec from upstream ALPN")
	}
	if httpOptions.GetUseDownstreamProtocolConfig() != nil {
		t.Fatal("TLS proxy cluster must not reuse the independently negotiated downstream protocol")
	}
	if httpOptions.GetUpstreamHttpProtocolOptions().GetAutoSni() {
		t.Fatal("TLS proxy cluster must not derive SNI from CONNECT authority")
	}
	if httpOptions.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
		t.Fatal("TLS proxy cluster must not derive SAN validation from CONNECT authority")
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := got.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode upstream TLS context: %v", err)
	}
	assertSandboxUpstreamTLSParameters(t, tlsContext.GetCommonTlsContext().GetTlsParams())
	// Proxy hostnames also share one TLS context; an absent wrapper enables the cache.
	if keys := tlsContext.GetMaxSessionKeys(); keys == nil || keys.GetValue() != 0 {
		t.Fatalf("max session keys = %v, want explicit zero to prevent cross-SNI session reuse", keys)
	}
	common := tlsContext.GetCommonTlsContext()
	if got, want := common.GetTlsParams().GetTlsMinimumProtocolVersion(), tlsv3.TlsParameters_TLSv1_2; got != want {
		t.Fatalf("minimum TLS version = %v, want %v", got, want)
	}
	if got, want := common.GetValidationContext().GetTrustedCa().GetFilename(), security.GetOSRootFilePath(); got != want {
		t.Fatalf("trusted CA = %q, want OS roots %q", got, want)
	}
	if len(common.GetAlpnProtocols()) != len(util.ALPNHttp) {
		t.Fatalf("ALPN protocols = %v, want %v", common.GetAlpnProtocols(), util.ALPNHttp)
	}
	for i := range util.ALPNHttp {
		if common.GetAlpnProtocols()[i] != util.ALPNHttp[i] {
			t.Fatalf("ALPN protocols = %v, want %v", common.GetAlpnProtocols(), util.ALPNHttp)
		}
	}
}

func TestSandboxClusters_AppliesInboundEnvoyFilterPatches(t *testing.T) {
	mesh := testMesh()
	mesh.RootNamespace = "agentio-system"
	cg := NewConfigGenTest(t, TestOptions{
		MeshConfig: mesh,
		ConfigString: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: sandbox-cluster-patch
  namespace: agentio-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: SIDECAR_INBOUND
      cluster:
        name: tls_proxy_originate
    patch:
      operation: MERGE
      value:
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            common_tls_context:
              validation_context:
                trusted_ca:
                  inline_string: proxy-ca
`,
	})
	proxy := cg.SetupProxy(&model.Proxy{
		Type:            model.Waypoint,
		ConfigNamespace: "agentio-system",
		Labels: map[string]string{
			agentio.LabelSandboxEgress:               "true",
			"gateway.networking.k8s.io/gateway-name": "egress-gateway",
		},
	})

	var got *cluster.Cluster
	for _, c := range cg.Clusters(proxy) {
		if c.GetName() == tlsProxyOriginateCluster {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatalf("cluster %q not found", tlsProxyOriginateCluster)
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := got.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode upstream TLS context: %v", err)
	}
	if got := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetInlineString(); got != "proxy-ca" {
		t.Fatalf("trusted CA inline string = %q, want proxy-ca", got)
	}
}

func TestSandboxClusters_SniTrafficPolicyDoesNotAddInternalCluster(t *testing.T) {
	previous := features.EnableSniTrafficPolicy
	features.EnableSniTrafficPolicy = true
	t.Cleanup(func() { features.EnableSniTrafficPolicy = previous })

	cb := &ClusterBuilder{
		proxyMetadata: &model.NodeMetadata{},
		req: &model.PushRequest{Push: &model.PushContext{
			Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
		}},
	}
	clusters := sandboxClusters(cb, nil)
	if got, want := len(clusters), 5; got != want {
		t.Fatalf("feature-enabled sandbox clusters = %d, want %d without a policy-only internal hop", got, want)
	}
	for _, c := range clusters {
		if c.GetName() == "agentio-sni-tls-termination" {
			t.Fatal("SNI policy must select the TLS termination chain directly, not an internal cluster")
		}
	}
}

func assertSandboxUpstreamTLSParameters(t *testing.T, params *tlsv3.TlsParameters) {
	t.Helper()
	if got := params.GetTlsMinimumProtocolVersion(); got != tlsv3.TlsParameters_TLSv1_2 {
		t.Errorf("minimum TLS version = %v, want TLSv1_2", got)
	}
	if got := params.GetTlsMaximumProtocolVersion(); got != tlsv3.TlsParameters_TLSv1_3 {
		t.Errorf("maximum TLS version = %v, want TLSv1_3", got)
	}
	want := []string{
		"ECDHE-ECDSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"AES128-GCM-SHA256",
		"AES256-GCM-SHA384",
	}
	if got := params.GetCipherSuites(); !slices.Equal(got, want) {
		t.Errorf("upstream cipher suites = %v, want %v", got, want)
	}
}

func TestSandboxClusters_UpstreamTLSPerGateway(t *testing.T) {
	settings := &extensions.UpstreamTlsSettings{
		MaxProtocolVersion: extensions.UpstreamTlsSettings_TLSV1_2,
		CipherSuites:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
	}
	push := &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
		AgentioConfig: &model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{
			EgressGateways: []*extensions.EgressGateway{{Name: "egress-gw", Namespace: "istio-system", UpstreamTls: settings}},
		}},
	}
	cb := &ClusterBuilder{req: &model.PushRequest{Push: push}}
	for _, tt := range []struct {
		name    string
		matched bool
	}{{"matching gateway", true}, {"other gateway", false}} {
		t.Run(tt.name, func(t *testing.T) {
			proxy := sandboxEgressNode()
			if !tt.matched {
				proxy.VerifiedIdentity.Namespace = "other"
			}
			count := 0
			for _, c := range sandboxClusters(cb, proxy) {
				if c.Name != tlsOriginateCluster && c.Name != tlsProxyOriginateCluster {
					continue
				}
				count++
				ctx := &tlsv3.UpstreamTlsContext{}
				if err := c.GetTransportSocket().GetTypedConfig().UnmarshalTo(ctx); err != nil {
					t.Fatal(err)
				}
				params := ctx.GetCommonTlsContext().GetTlsParams()
				if !tt.matched {
					assertSandboxUpstreamTLSParameters(t, params)
					continue
				}
				if params.GetTlsMinimumProtocolVersion() != tlsv3.TlsParameters_TLSv1_2 || params.GetTlsMaximumProtocolVersion() != tlsv3.TlsParameters_TLSv1_2 {
					t.Fatalf("unexpected TLS range: %v", params)
				}
				if !slices.Equal(params.GetCipherSuites(), settings.CipherSuites) {
					t.Fatalf("cipher list was not replaced: %v", params)
				}
				if ctx.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() != security.GetOSRootFilePath() || ctx.GetMaxSessionKeys() == nil || ctx.GetMaxSessionKeys().GetValue() != 0 {
					t.Fatal("TLS security settings changed")
				}
			}
			if count != 2 {
				t.Fatalf("tested %d TLS clusters, want 2", count)
			}
		})
	}
	for _, settings := range []*extensions.UpstreamTlsSettings{nil, {}, {CipherSuites: []string{}}} {
		assertSandboxUpstreamTLSParameters(t, sandboxUpstreamTLSParameters(settings))
	}
	params := sandboxUpstreamTLSParameters(&extensions.UpstreamTlsSettings{MinProtocolVersion: extensions.UpstreamTlsSettings_TLSV1_3})
	if params.GetTlsMinimumProtocolVersion() != tlsv3.TlsParameters_TLSv1_3 || params.GetTlsMaximumProtocolVersion() != tlsv3.TlsParameters_TLSv1_3 {
		t.Fatalf("TLS 1.3-only settings: %v", params)
	}
}
