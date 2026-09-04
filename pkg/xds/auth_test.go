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

package xds

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

func requestWithMetadata(podName, namespace, nodeName string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{
		Id: "sidecar~10.0.0.1~client-pod.demo~demo.svc.cluster.local",
		Metadata: &structpb.Struct{Fields: map[string]*structpb.Value{
			"POD_NAME":      structpb.NewStringValue(podName),
			"POD_NAMESPACE": structpb.NewStringValue(namespace),
			"NODE_NAME":     structpb.NewStringValue(nodeName),
		}},
	}}
}

func TestClientVersionFromNode(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*discoveryv3.DeltaDiscoveryRequest)
		version string
	}{
		{name: "istio version metadata", mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
			request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
		}, version: "1.24.2"},
		{name: "user agent fallback", mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
			request.Node.UserAgentVersionType = &corev3.Node_UserAgentVersion{UserAgentVersion: "1.30.0"}
		}, version: "1.30.0"},
		{name: "metadata wins over user agent", mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
			request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
			request.Node.UserAgentVersionType = &corev3.Node_UserAgentVersion{UserAgentVersion: "1.30.0"}
		}, version: "1.24.2"},
		{name: "absent", mutate: func(*discoveryv3.DeltaDiscoveryRequest) {}, version: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := requestWithMetadata("client-pod", "demo", "node-a")
			tt.mutate(request)
			if version := clientVersion(request.GetNode()); version != tt.version {
				t.Fatalf("clientVersion() = %q, want %q", version, tt.version)
			}
		})
	}
}

func TestScopeAllowsNamespaceAuthorization(t *testing.T) {
	resourceFor := func(namespace string) model.Resource {
		return model.Resource{
			Key: model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "policy"},
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope: model.AuthorizationScopeNamespace, Namespace: namespace,
			}},
		}
	}
	serviceAccountScope := model.ClientScope{
		Class: model.ClientDedicatedZTunnel,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "app",
			},
		},
		SandboxUID: "uid-a",
	}

	if !scopeAllows(serviceAccountScope, resourceFor("demo")) {
		t.Fatal("service account scope lost its namespace identity visibility")
	}
	if scopeAllows(serviceAccountScope, resourceFor("other")) {
		t.Fatal("service account scope received another namespace Authorization")
	}
}

func TestScopeAllowsFullWDSOnlyForGateways(t *testing.T) {
	address := model.Resource{
		Key: model.ResourceKey{TypeURL: model.AddressType, Name: "uid-a"},
		Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			SandboxUID: "uid-a", NodeName: "node-b",
		}},
	}
	sniPolicy := model.Resource{
		Key: model.ResourceKey{TypeURL: model.SniTrafficPolicyType, Name: "demo/policy"},
	}
	gateway := model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "agentio-system/egress"}
	sandbox := model.ClientScope{Class: model.ClientDedicatedZTunnel, SandboxUID: "uid-other"}
	node := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}

	if !scopeAllows(gateway, address) {
		t.Fatal("gateway lost full WDS snapshot visibility")
	}
	if scopeAllows(sandbox, address) {
		t.Fatal("sandbox client must not see WDS snapshot members beyond its subject")
	}
	if scopeAllows(node, address) {
		t.Fatal("node client must not see WDS snapshot members beyond its subject")
	}
	if !scopeAllows(sandbox, sniPolicy) || !scopeAllows(node, sniPolicy) || !scopeAllows(gateway, sniPolicy) {
		t.Fatal("global SNI resources must stay visible to every client class")
	}
}

func TestScopeNamespaceByClass(t *testing.T) {
	serviceAccount := model.ClientScope{
		Class: model.ClientDedicatedZTunnel,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "app",
			},
		},
		SandboxUID: "uid-a",
	}
	node := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a",
		Principal: serviceAccount.Principal}

	if got, found := scopeNamespace(serviceAccount); !found || got != "demo" {
		t.Fatalf("service account scope namespace = %q, found=%t", got, found)
	}
	if got, found := scopeNamespace(node); found {
		t.Fatalf("node scope owns namespace %q", got)
	}
}
