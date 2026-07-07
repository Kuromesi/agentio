package sandbox

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/sandbox/extensions"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/workloadapi"
	"istio.io/istio/pkg/workloadapi/security"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	extensionPrefix         = "type.googleapis.com/istio.alibabacloud.extensions.v1."
	trafficPolicyExtension  = extensionPrefix + "TrafficPolicyExtension"
	metadataExtension       = extensionPrefix + "Metadata"
	egressPoliciesExtension = extensionPrefix + "EgressPolicies"

	LabelSandboxProxyType = "networking.agents.kruise.io/proxy-type"
	LabelSandboxEgress    = "networking.agents.kruise.io/sandbox-egress"

	MeshInternalTrafficPolicyPassthrough = "PASSTHROUGH"
	MeshInternalTrafficPolicyPeerAware   = "PEER_AWARE"
)

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

// IsAllowedOnDemandDomain reports whether proxy is permitted to pull an
// on-demand cert for the given SNI domain — i.e. proxy belongs to an
// EgressGateway whose tls_termination.include_hosts covers domain. Wildcards
// in include_hosts (e.g. "*.example.com") use the same matching rules as
// host.Name.SubsetOf.
func IsAllowedOnDemandDomain(proxy *model.Proxy, push *model.PushContext, domain string) bool {
	if push == nil || push.SandboxConfig == nil {
		return false
	}
	g := FindEgressGatewayForProxy(proxy, push.SandboxConfig.GetEgressGateways())
	if g == nil {
		return false
	}
	cfg := g.GetTlsTermination()
	if cfg == nil {
		return false
	}
	needle := host.Name(domain)
	for _, h := range cfg.GetIncludeHosts() {
		if needle.SubsetOf(host.Name(h)) {
			return true
		}
	}
	return false
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

func MeshInternalTrafficPolicyFromString(s string) extensions.MeshInternalTrafficPolicy {
	if v, ok := extensions.MeshInternalTrafficPolicy_value["MESH_INTERNAL_"+s]; ok {
		return extensions.MeshInternalTrafficPolicy(v)
	}
	return extensions.MeshInternalTrafficPolicy_MESH_INTERNAL_PEER_AWARE
}

func NewResourceMetadataExtension(labels map[string]string, internalPolicy extensions.MeshInternalTrafficPolicy) *workloadapi.Extension {
	pbBytes, _ := proto.Marshal(&extensions.Metadata{
		Labels:                    labels,
		MeshInternalTrafficPolicy: internalPolicy,
	})
	return &workloadapi.Extension{
		Name: "metadata",
		Config: &anypb.Any{
			TypeUrl: metadataExtension,
			Value:   pbBytes,
		},
	}
}
