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
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/kind"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/workloadapi"
	"istio.io/istio/pkg/workloadapi/security"
)

const (
	extensionPrefix           = "type.googleapis.com/kruise.networking.extensions.v1."
	trafficPolicyExtension    = extensionPrefix + "TrafficPolicyExtension"
	workloadMetadataExtension = extensionPrefix + "WorkloadMetadata"
	egressPoliciesExtension   = extensionPrefix + "EgressPolicies"
	PolicyReferenceTypeURL    = extensionPrefix + "PolicyReference"

	SniTrafficPolicyReferenceExtensionName = "sni-traffic-policy"
	SniTrafficPolicyCapability             = "sni_traffic_policy"

	LabelSandboxProxyType = "networking.agents.kruise.io/proxy-type"
	LabelSandboxEgress    = "networking.agents.kruise.io/sandbox-egress"

	MeshInternalTrafficPolicyPassthrough = "PASSTHROUGH"
	MeshInternalTrafficPolicyPeerAware   = "PEER_AWARE"
)

type policyReferenceContract struct {
	capability    string
	extensionName string
}

var policyReferenceContractByTypeURL = map[string]policyReferenceContract{
	xdsmodel.SniTrafficPolicyType: {
		capability:    SniTrafficPolicyCapability,
		extensionName: SniTrafficPolicyReferenceExtensionName,
	},
}

func IsSandboxDedicatedProxy(proxy *model.Proxy) bool {
	return proxy.Labels[LabelSandboxProxyType] == "ztunnel"
}

func IsSandboxEgress(proxy *model.Proxy) bool {
	return proxy.Labels[LabelSandboxEgress] == "true"
}

func IsWaypointWorkload(workload *model.WorkloadInfo) bool {
	return workload.Labels[label.GatewayManaged.Name] == constants.ManagedGatewayMeshControllerLabel ||
		workload.Labels[LabelSandboxEgress] == "true"
}

func IsWaypointService(service *v1.Service) bool {
	return service.Labels[label.GatewayManaged.Name] == constants.ManagedGatewayMeshControllerLabel ||
		service.Labels[LabelSandboxEgress] == "true"
}

func ShouldPushAuthorizationPolicy(proxy *model.Proxy, policy *model.WorkloadAuthorization, rootNamespace string) bool {
	// namespace scope but not in the same namespace with proxy
	if policy.Authorization.Namespace != rootNamespace &&
		policy.Authorization.Namespace != proxy.Metadata.Namespace {
		return false
	}

	selector := policy.LabelSelector.GetLabelSelector()
	// namespace scope or global scope, we always return
	if len(selector) == 0 && policy.Selector == nil {
		return true
	}

	if policy.Selector != nil && !policy.Selector.Matches(labels.Set(proxy.Labels)) {
		return false
	}

	if len(selector) != 0 && !labels.SelectorFromSet(labels.Set(selector)).Matches(labels.Set(proxy.Labels)) {
		// check if label selector matches
		return false
	}

	return true
}

func ShouldPushWorkload(proxy *model.Proxy, workload *model.WorkloadInfo) bool {
	// we always return workload with waypoints
	if workload.Workload.Waypoint != nil {
		return true
	}

	// workloadentries are also needed since the traffic can only handle by us
	if workload.Source == kind.WorkloadEntry {
		return true
	}

	// return waypoints
	if IsWaypointWorkload(workload) {
		return true
	}

	name, namespace, ok := ExtractProxyMeta(proxy)
	if !ok {
		log.Warnf("Invalid id format, id: %s", proxy.ID)
		return false
	}

	// return the workload itself
	return name == workload.Workload.Name &&
		namespace == workload.Workload.Namespace
}

func ShouldPushService(proxy *model.Proxy, service *model.ServiceInfo) bool {
	// we always return service with waypoints
	if service.Service.Waypoint != nil {
		return true
	}

	// return waypoints
	if service.IsWaypoint {
		return true
	}

	// serviceentries are also needed since the traffic can only handle by us
	if service.Source.Kind == kind.ServiceEntry {
		return true
	}

	// push service of the proxy
	if service.GetLabelSelector() != nil && service.GetNamespace() == proxy.Metadata.Namespace {
		sel := labels.SelectorFromSet(labels.Set(service.GetLabelSelector()))
		return sel.Matches(labels.Set(proxy.Labels))
	}
	return false
}

func ExtractProxyMeta(proxy *model.Proxy) (string, string, bool) {
	parts := strings.Split(proxy.ID, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// FindEgressGatewayForProxy returns the EgressGateway matching the proxy's
// verified SPIFFE identity (ServiceAccount + Namespace), or nil if none
// matches. By convention an EgressGateway's name equals the ServiceAccount
// used by its pods — same rule as onDemandCertController.Authorize, so listener
// and SDS paths can't drift. Requires mTLS-verified identity; plaintext or
// unverified proxies are rejected.
func FindEgressGatewayForProxy(proxy *model.Proxy, gateways []*extensions.EgressGateway) *extensions.EgressGateway {
	if proxy == nil || proxy.VerifiedIdentity == nil || len(gateways) == 0 {
		return nil
	}
	sa := proxy.VerifiedIdentity.ServiceAccount
	namespace := proxy.VerifiedIdentity.Namespace
	for _, g := range gateways {
		if g.GetName() == sa && g.GetNamespace() == namespace {
			return g
		}
	}
	return nil
}

func BuildProxyWorkloadKey(proxy *model.Proxy) (string, bool) {
	proxyName, proxyNamespace, ok := ExtractProxyMeta(proxy)
	if !ok {
		return "", false
	}
	return proxy.GetClusterID().String() + "//Pod/" + proxyNamespace + "/" + proxyName, true
}

func NewTrafficPolicyExtension(priority int64, mode extensions.TrafficPolicyMode) *security.Extension {
	pbBytes, _ := proto.Marshal(&extensions.TrafficPolicyExtension{
		Priority: int32(priority),
		Mode:     mode,
	})
	return &security.Extension{
		Name: "traffic-policy",
		Config: &anypb.Any{
			TypeUrl: trafficPolicyExtension,
			Value:   pbBytes,
		},
	}
}

func NewEgressPoliciesExtension(policies []*extensions.EgressPolicy) *workloadapi.Extension {
	pbBytes, _ := proto.Marshal(&extensions.EgressPolicies{EgressPolicies: policies})
	return &workloadapi.Extension{
		Name: "egress-policies",
		Config: &anypb.Any{
			TypeUrl: egressPoliciesExtension,
			Value:   pbBytes,
		},
	}
}

func NewPolicyReferenceExtension(name string, reference *extensions.PolicyReference) *workloadapi.Extension {
	if name == "" || reference == nil || reference.GetTypeUrl() == "" || len(reference.GetResourceNames()) == 0 {
		return nil
	}
	pbBytes, err := proto.Marshal(reference)
	if err != nil {
		return nil
	}
	return &workloadapi.Extension{
		Name: name,
		Config: &anypb.Any{
			TypeUrl: PolicyReferenceTypeURL,
			Value:   pbBytes,
		},
	}
}

func SupportsPolicyRuntime(metadata *model.NodeMetadata) bool {
	if metadata == nil || metadata.MetadataDiscovery == nil || !bool(*metadata.MetadataDiscovery) {
		return false
	}
	return len(metadata.PolicyRuntimeCapabilities) > 0
}

func SupportsPolicyCapability(metadata *model.NodeMetadata, capability string) bool {
	if !SupportsPolicyRuntime(metadata) {
		return false
	}
	for _, supported := range metadata.PolicyRuntimeCapabilities {
		if supported == capability {
			return true
		}
	}
	return false
}

// PolicyReferenceExtensionsForProxy emits one Workload extension per policy
// type implemented by this proxy. Unknown types are omitted rather than making
// an older runtime subscribe to resources it cannot enforce or wait for them
// during readiness.
func PolicyReferenceExtensionsForProxy(
	metadata *model.NodeMetadata,
	references []*extensions.PolicyReference,
) []*workloadapi.Extension {
	if !SupportsPolicyRuntime(metadata) || len(references) == 0 {
		return nil
	}
	result := make([]*workloadapi.Extension, 0, len(references))
	for _, reference := range references {
		contract, found := policyReferenceContractByTypeURL[reference.GetTypeUrl()]
		if !found || !SupportsPolicyCapability(metadata, contract.capability) {
			continue
		}
		if extension := NewPolicyReferenceExtension(contract.extensionName, reference); extension != nil {
			result = append(result, extension)
		}
	}
	return result
}

func MeshInternalTrafficPolicyFromString(s string) extensions.MeshInternalTrafficPolicy {
	if v, ok := extensions.MeshInternalTrafficPolicy_value["MESH_INTERNAL_"+s]; ok {
		return extensions.MeshInternalTrafficPolicy(v)
	}
	return extensions.MeshInternalTrafficPolicy_MESH_INTERNAL_PEER_AWARE
}

func NewWorkloadMetadataExtension(labels map[string]string, internalPolicy extensions.MeshInternalTrafficPolicy) *workloadapi.Extension {
	pbBytes, _ := proto.Marshal(&extensions.WorkloadMetadata{
		Labels:                    labels,
		MeshInternalTrafficPolicy: internalPolicy,
	})
	return &workloadapi.Extension{
		Name: "workload-metadata",
		Config: &anypb.Any{
			TypeUrl: workloadMetadataExtension,
			Value:   pbBytes,
		},
	}
}
