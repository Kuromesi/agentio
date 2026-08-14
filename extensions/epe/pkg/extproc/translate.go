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
func translateRequestHeadersResult(reqHeadersRes *engine.RequestHeadersResult, loggerD logr.Logger, peer filter.Peer) []*extProcPb.ProcessingResponse {
	if reqHeadersRes.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(reqHeadersRes.Reply)}
	}
	if len(reqHeadersRes.HeaderOps) == 0 && reqHeadersRes.Body == nil {
		if reqHeadersRes.Disposition == engine.DispositionPassthrough {
			loggerD.Info("No filter produced mutations; passthrough", "pod", peer.Pod.String())
		}
		return defaultPassThrough
	}
	mut, clear := headerMutationFromOps(reqHeadersRes.HeaderOps)
	common := &extProcPb.CommonResponse{
		HeaderMutation:  mut,
		ClearRouteCache: clear || reqHeadersRes.ClearRouteCache,
	}
	if reqHeadersRes.Body != nil {
		// A headers-phase body mutation is silently dropped under plain
		// CONTINUE; Envoy only honors it with CONTINUE_AND_REPLACE.
		common.Status = extProcPb.CommonResponse_CONTINUE_AND_REPLACE
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: reqHeadersRes.Body},
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
func translateRequestBodyResult(reqBodyRes *engine.RequestBodyResult) []*extProcPb.ProcessingResponse {
	if reqBodyRes.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(reqBodyRes.Reply)}
	}
	if len(reqBodyRes.HeaderOps) == 0 && reqBodyRes.Body == nil {
		return defaultPassThroughBody
	}
	mut, clear := headerMutationFromOps(reqBodyRes.HeaderOps)
	common := &extProcPb.CommonResponse{
		HeaderMutation:  mut,
		ClearRouteCache: clear || reqBodyRes.ClearRouteCache,
	}
	if reqBodyRes.Body != nil {
		// Rewriting a BUFFERED body without a matching content-length is a
		// hard error (500), so the adapter sets both together.
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: reqBodyRes.Body},
		}
		if common.HeaderMutation == nil {
			common.HeaderMutation = &extProcPb.HeaderMutation{}
		}
		common.HeaderMutation.SetHeaders = append(common.HeaderMutation.SetHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      "content-length",
				RawValue: []byte(strconv.Itoa(len(reqBodyRes.Body))),
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

// translateResponseHeadersResult emits a blocking reply, response mutations,
// or a bare acknowledgement. It never clears the request-side route cache.
func translateResponseHeadersResult(respHeadersRes *engine.ResponseHeadersResult) []*extProcPb.ProcessingResponse {
	if respHeadersRes.Disposition == engine.DispositionBlocked {
		// Envoy holds the upstream response headers while awaiting our reply, so
		// this local reply genuinely replaces them. HeaderOps are ignored: the
		// response being mutated no longer goes downstream.
		return []*extProcPb.ProcessingResponse{immediateFromReply(respHeadersRes.Reply)}
	}
	if len(respHeadersRes.HeaderOps) == 0 && respHeadersRes.Body == nil {
		return emptyResponseHeadersAck
	}
	mut, _ := headerMutationFromOps(respHeadersRes.HeaderOps)
	common := &extProcPb.CommonResponse{HeaderMutation: mut}
	if respHeadersRes.Body != nil {
		common.Status = extProcPb.CommonResponse_CONTINUE_AND_REPLACE
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: respHeadersRes.Body},
		}
	}
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{
				Response: common,
			},
		},
	}}
}

// emptyResponseHeadersAck is the immutable bare acknowledgement for response headers.
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
		case filter.HeaderAdd:
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
