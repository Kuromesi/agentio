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
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

func clientVersion(node *corev3.Node) string {
	version := metadataString(node.GetMetadata(), "ISTIO_VERSION")
	if version == "" {
		version = node.GetUserAgentVersion()
	}
	return version
}

func metadataString(metadata *structpb.Struct, key string) string {
	if metadata == nil {
		return ""
	}
	return metadata.GetFields()[key].GetStringValue()
}

func allowedType(class model.ClientClass, typeURL string) bool {
	_, allowed := typeAccess(class, typeURL)
	return allowed
}

func typeAccess(class model.ClientClass, typeURL string) (known, allowed bool) {
	switch typeURL {
	case model.AddressType, model.WorkloadAuthorizationType:
		return true, true
	case model.WorkloadType, model.ClusterType, model.EndpointType, model.ListenerType, model.RouteType, model.SecretType,
		model.ExtensionConfigurationType, model.ProxyConfigType, model.SniTrafficPolicyType:
		return true, class == model.ClientEgressGateway
	default:
		return false, false
	}
}

func scopeNamespace(scope model.ClientScope) (string, bool) {
	if scope.Class != model.ClientDedicatedZTunnel || scope.Principal.Kind != model.PrincipalServiceAccount {
		return "", false
	}
	return scope.Principal.ServiceAccount.Namespace, true
}

func scopeAllows(scope model.ClientScope, resource model.Resource) bool {
	if resource.Facts.GatewayOwner != "" {
		return scope.Class == model.ClientEgressGateway && resource.Facts.GatewayOwner == scope.GatewayKey
	}
	switch resource.Key.TypeURL {
	case model.AddressType, model.WorkloadType:
		if scope.Class == model.ClientEgressGateway {
			return true
		}
		return workloadMatchesScope(scope, resource)
	case model.WorkloadAuthorizationType:
		if scope.Class == model.ClientEgressGateway {
			return true
		}
		authorization := resource.Facts.Authorization
		if authorization == nil {
			return false
		}
		if authorization.Scope == model.AuthorizationScopeGlobal {
			return true
		}
		namespace, found := scopeNamespace(scope)
		return found && authorization.Scope == model.AuthorizationScopeNamespace && authorization.Namespace == namespace
	case model.SniTrafficPolicyType:
		return true
	default:
		return false
	}
}
