package route

import (
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/protocol"
)

// BuildDefaultHTTPSandboxRoute builds a default route for the sandbox egress
// catchall path. It starts from the inbound route base (which provides the
// retry policy and decorator) but calls setTimeout to apply the timeout using
// the legacy MaxGrpcTimeout path instead of MaxStreamDuration. This ensures
// usingNewTimeouts()=false in Envoy so that route.timeout() is honored.
func BuildDefaultHTTPSandboxRoute(proxy *model.Proxy, clusterName string, timeout *durationpb.Duration) *routev3.Route {
	out := BuildDefaultHTTPInboundRoute(proxy, clusterName, clusterName, protocol.HTTP)
	if timeout != nil {
		setTimeout(out.GetRoute(), timeout, proxy)
		// setTimeout does not clear MaxStreamDuration set by BuildDefaultHTTPInboundRoute.
		// When present (even zero-valued), Envoy enters "new timeout mode" and ignores
		// route.timeout() entirely. Clear it so route timeout is honored.
		out.GetRoute().MaxStreamDuration = nil
	}
	return out
}
