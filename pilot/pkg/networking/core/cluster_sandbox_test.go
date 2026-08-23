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
	"google.golang.org/protobuf/types/known/durationpb"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
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
	if got, want := len(clusters), 4; got != want {
		t.Fatalf("feature-enabled sandbox clusters = %d, want %d without a policy-only internal hop", got, want)
	}
	for _, c := range clusters {
		if c.GetName() == "agentio-sni-tls-termination" {
			t.Fatal("SNI policy must select the TLS termination chain directly, not an internal cluster")
		}
	}
}
