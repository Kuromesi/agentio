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
