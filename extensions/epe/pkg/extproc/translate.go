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

// Translation between the engine's plain results and ext_proc protos.
// This is the single place mutations become wire format — the reason
// filters can stay proto-free.
package extproc

import (
	"strconv"

	"github.com/go-logr/logr"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoyTypeV3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// routeAffectingHeaders force clear_route_cache: a rewrite of any of these
// silently misses routing when an earlier filter cached the route.
var routeAffectingHeaders = map[string]bool{
	":path":      true,
	":authority": true,
	":method":    true,
	":scheme":    true,
	"host":       true,
}

// translateRequestHeadersResult maps an RequestHeadersResult to the headers-phase response
// list.
func translateRequestHeadersResult(er *engine.RequestHeadersResult, loggerD logr.Logger, peer filter.Peer) []*extProcPb.ProcessingResponse {
	if er.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(er.Reply)}
	}
	if len(er.HeaderOps) == 0 && er.Body == nil {
		if er.Disposition == engine.DispositionPassthrough {
			loggerD.Info("No filter produced mutations; passthrough", "pod", peer.Pod.String())
		}
		return defaultPassThrough
	}
	mut, clear := headerMutationFromOps(er.HeaderOps)
	common := &extProcPb.CommonResponse{
		HeaderMutation:  mut,
		ClearRouteCache: clear || er.ClearRouteCache,
	}
	if er.Body != nil {
		// A headers-phase body mutation is silently dropped under plain
		// CONTINUE; Envoy only honors it with CONTINUE_AND_REPLACE.
		common.Status = extProcPb.CommonResponse_CONTINUE_AND_REPLACE
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: er.Body},
		}
	}
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extProcPb.HeadersResponse{
				Response: common,
			},
		},
	}}
}

// translateRequestBodyResult maps a RequestBodyResult to the body-phase response list.
func translateRequestBodyResult(br *engine.RequestBodyResult) []*extProcPb.ProcessingResponse {
	if br.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(br.Reply)}
	}
	if len(br.HeaderOps) == 0 && br.Body == nil {
		return defaultPassThroughBody
	}
	mut, clear := headerMutationFromOps(br.HeaderOps)
	common := &extProcPb.CommonResponse{
		HeaderMutation:  mut,
		ClearRouteCache: clear || br.ClearRouteCache,
	}
	if br.Body != nil {
		// Rewriting a BUFFERED body without a matching content-length is a
		// hard error (500), so the adapter sets both together.
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: br.Body},
		}
		if common.HeaderMutation == nil {
			common.HeaderMutation = &extProcPb.HeaderMutation{}
		}
		common.HeaderMutation.SetHeaders = append(common.HeaderMutation.SetHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      "content-length",
				RawValue: []byte(strconv.Itoa(len(br.Body))),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_RequestBody{
			RequestBody: &extProcPb.BodyResponse{
				Response: common,
			},
		},
	}}
}

// translateResponseHeadersResult maps a ResponseHeadersResult to the
// response-headers-phase response list.
//
// Three deliberate asymmetries with the request path:
//
//   - headerMutationFromOps's route-affecting bool is discarded.
//     clear_route_cache is a documented no-op in the response direction (only
//     the decoding state overrides the empty virtual base), and routing is long
//     decided by the time response headers exist, so routeAffectingHeaders is
//     meaningless here.
//   - CommonResponse_CONTINUE_AND_REPLACE is never emitted: on the response path
//     it force-disables all further response processing.
//   - No BodyMutation: the extension never rewrites a response body, and a
//     mismatched content-length would corrupt framing.
func translateResponseHeadersResult(rr *engine.ResponseHeadersResult) []*extProcPb.ProcessingResponse {
	if rr.Disposition == engine.DispositionBlocked {
		// Envoy holds the upstream response headers while awaiting our reply, so
		// this local reply genuinely replaces them. HeaderOps are ignored: the
		// response being mutated no longer goes downstream.
		return []*extProcPb.ProcessingResponse{immediateFromReply(rr.Reply)}
	}
	if len(rr.HeaderOps) == 0 {
		return emptyResponseHeadersAck
	}
	mut, _ := headerMutationFromOps(rr.HeaderOps)
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{
				Response: &extProcPb.CommonResponse{HeaderMutation: mut},
			},
		},
	}}
}

// emptyResponseHeadersAck is the bare acknowledgement for the response-headers
// phase. Shared rather than rebuilt per call, matching defaultPassThrough and
// defaultPassThroughBody: immutable and safe across goroutines, because gRPC
// serializes but does not mutate the proto. Nothing may attach a ModeOverride to
// it — mode_override belongs to a request-headers reply, and cloneResponse exists
// for the one site that needs a mutable copy.
var emptyResponseHeadersAck = []*extProcPb.ProcessingResponse{{
	Response: &extProcPb.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &extProcPb.HeadersResponse{},
	},
}}

// headerMutationFromOps renders folded ops as one proto HeaderMutation and
// reports whether a route-affecting header was touched.
func headerMutationFromOps(ops []filter.HeaderOp) (*extProcPb.HeaderMutation, bool) {
	mut := &extProcPb.HeaderMutation{}
	clear := false
	for _, op := range ops {
		if routeAffectingHeaders[op.Name] {
			clear = true
		}
		switch op.Kind {
		case filter.HeaderSet:
			mut.SetHeaders = append(mut.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: op.Name, RawValue: []byte(op.Value)},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		case filter.HeaderAppend:
			mut.SetHeaders = append(mut.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: op.Name, RawValue: []byte(op.Value)},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		case filter.HeaderRemove:
			mut.RemoveHeaders = append(mut.RemoveHeaders, op.Name)
		}
	}
	return mut, clear
}

// immediateFromReply renders a terminal Reply as an ImmediateResponse.
func immediateFromReply(r filter.Reply) *extProcPb.ProcessingResponse {
	immediate := &extProcPb.ImmediateResponse{
		Status:  &envoyTypeV3.HttpStatus{Code: envoyTypeV3.StatusCode(r.Status)},
		Body:    r.Body,
		Details: r.Details,
	}
	if len(r.Headers) > 0 {
		hm := &extProcPb.HeaderMutation{}
		for k, v := range r.Headers {
			hm.SetHeaders = append(hm.SetHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{Key: k, RawValue: []byte(v)},
			})
		}
		immediate.Headers = hm
	}
	return &extProcPb.ProcessingResponse{
		Response: &extProcPb.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: immediate,
		},
	}
}
