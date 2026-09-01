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
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/wellknown"
)

func TestSandboxClusters_RegistersPlaintextHTTPDynamicForwardProxy(t *testing.T) {
	cb := &ClusterBuilder{req: &model.PushRequest{Push: &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
	}}}

	var got *cluster.Cluster
	for _, c := range sandboxClusters(cb) {
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
	for _, c := range sandboxClusters(cb) {
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
}

func TestSandboxClusters_TLSProxyOriginationUsesOriginalDestination(t *testing.T) {
	cb := &ClusterBuilder{req: &model.PushRequest{Push: &model.PushContext{
		Mesh: &meshconfig.MeshConfig{ConnectTimeout: durationpb.New(time.Second)},
	}}}

	var got *cluster.Cluster
	for _, c := range sandboxClusters(cb) {
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
	clusters := sandboxClusters(cb)
	if got, want := len(clusters), 5; got != want {
		t.Fatalf("feature-enabled sandbox clusters = %d, want %d without a policy-only internal hop", got, want)
	}
	for _, c := range clusters {
		if c.GetName() == "agentio-sni-tls-termination" {
			t.Fatal("SNI policy must select the TLS termination chain directly, not an internal cluster")
		}
	}
}
