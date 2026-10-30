// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package extproc

import (
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

const (
	connectRequestBodyUnsupportedDetails  = "epe_connect_request_body_unsupported"
	connectResponseBodyUnsupportedDetails = "epe_connect_response_body_unsupported"
	connectBodyUnsupportedStatus          = 500
	missingIdentityDetails                = "epe_missing_source_identity"
	missingIdentityStatus                 = 403
)

// defaultPassThrough is the shared passthrough response returned when no
// filter produces mutations. It is immutable and safe to share across
// goroutines — gRPC serializes but does not mutate the proto.
var defaultPassThrough = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extProcPb.HeadersResponse{},
	}},
}

// Fixed local replies are read-only and shared, like defaultPassThrough.
var (
	connectRequestBodyUnsupportedReply = filter.Reply{
		Status: connectBodyUnsupportedStatus, Details: connectRequestBodyUnsupportedDetails,
	}
	connectResponseBodyUnsupportedReply = filter.Reply{
		Status: connectBodyUnsupportedStatus, Details: connectResponseBodyUnsupportedDetails,
	}
	missingIdentityDeny = []*extProcPb.ProcessingResponse{
		immediateFromReply(filter.Reply{Status: missingIdentityStatus, Details: missingIdentityDetails}),
	}
	invalidRouteUpstreamDeny = []*extProcPb.ProcessingResponse{
		immediateFromReply(filter.Reply{Status: 500, Details: "epe_invalid_route_upstream"}),
	}
	policyUnavailableDeny = []*extProcPb.ProcessingResponse{
		immediateFromReply(filter.Reply{Status: 503, Details: "epe_policy_unavailable"}),
	}
	emptyRequestTrailersAck = []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extProcPb.TrailersResponse{},
		},
	}}
	emptyResponseTrailersAck = []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extProcPb.TrailersResponse{},
		},
	}}
)

// defaultPassThroughBody is the empty-mutation body response.
var defaultPassThroughBody = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestBody{
		RequestBody: &extProcPb.BodyResponse{},
	}},
}

// defaultPassThroughResponseBody is the immutable empty-mutation response-body
// acknowledgement.
var defaultPassThroughResponseBody = []*extProcPb.ProcessingResponse{{
	Response: &extProcPb.ProcessingResponse_ResponseBody{
		ResponseBody: &extProcPb.BodyResponse{},
	},
}}

// emptyResponseHeadersAck is the immutable bare acknowledgement for response headers.
var emptyResponseHeadersAck = []*extProcPb.ProcessingResponse{{
	Response: &extProcPb.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &extProcPb.HeadersResponse{},
	},
}}

// Fixed local replies are read-only; callers clone before adding stream state.
var (
	invalidRouteMutationDeny      = immediateFromReply(filter.Reply{Status: 500, Details: "epe_invalid_route_mutation"})
	conflictingUpstreamTargetDeny = immediateFromReply(filter.Reply{Status: 500, Details: "epe_conflicting_upstream_target"})
)
