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
	"context"
	"strconv"
	"strings"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc/attributes"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/extensions/epe/pkg/logging"
)

const (
	// headerRequestID is Envoy's standard per-request correlation header.
	// Its value is attached to every log line in the ext-proc request path
	// (empty string when the header is absent).
	headerRequestID = "x-request-id"
	// logKeyRequestID is the structured-log key carrying the request ID.
	logKeyRequestID = "requestID"
	// requestBodyMode must stay BUFFERED: STREAMED releases acknowledged chunks
	// upstream before the verdict and prevents body-phase header mutations.
	requestBodyMode = extProcV3.ProcessingMode_BUFFERED
)

// HandleRequestHeaders resolves the caller identity, matches profiles into
// ordered units, and runs the ordered engine. All observations land in
// state.stream.Info; the stream loggers consume it once at stream end.
func (s *Server) HandleRequestHeaders(ctx context.Context, headers *extProcPb.HttpHeaders, attrs map[string]*structpb.Struct, state *streamState) ([]*extProcPb.ProcessingResponse, error) {
	// Tag every log line in this request's ext-proc path with the request
	// ID, and propagate it through ctx so downstream filters inherit it.
	requestID := extractRequestID(headers)
	logger := log.FromContext(ctx).WithValues(logKeyRequestID, requestID)
	ctx = log.IntoContext(ctx, logger)
	loggerD := logger.V(logging.DEBUG)
	// The log lines on this path are guarded rather than left to the level
	// check inside Info: Go builds the key-value slice at the call site, so an
	// unguarded line costs an allocation on every request even with the level
	// off.
	if loggerD.Enabled() {
		loggerD.Info("Handling request headers", "req.Attributes", attrs)
	}

	st := state.stream
	st.RequestID = requestID
	state.sawRequest = true

	peer, req := attributes.Extract(ctx, headers, attrs)
	st.Peer = peer
	st.Request = req

	if !peer.Valid() {
		// Fail open: without a source pod no SecurityProfile can be
		// applied. attributes.Extract already logged the operator-visible
		// missing-identity line.
		return defaultPassThrough, nil
	}

	// Profile lookup, rule matching and config projection all live behind
	// the resolver, so this adapter never names a policy type.
	pod := inputs.Pod{
		Name:      peer.Pod.Name,
		Namespace: peer.Pod.Namespace,
		IP:        peer.IP,
		Labels:    peer.Labels,
	}
	res, err := s.resolve(ctx, pod, &req)
	// Installed before the error is honoured: a resolver that fails may still
	// have matched rules worth recording, and finishStream promotes the error
	// to the disposition the logger reports. Without this, a resolve failure
	// is the one error class audit never sees. Guarded so a resolution that
	// carries no logger cannot erase one an earlier resolution installed.
	if res.StreamLogger != nil {
		state.streamLogger = res.StreamLogger
	}
	if err != nil {
		return nil, err
	}

	// Single VERBOSE summary line per request — pod identity, request
	// identity, and resolved unit count.
	if loggerV := logger.V(logging.VERBOSE); loggerV.Enabled() {
		loggerV.Info("Handling request",
			"pod", peer.Pod.Name, "namespace", peer.Pod.Namespace,
			"method", req.Method, "host", req.Host, "port", req.Port, "path", req.Path,
			"units", len(res.Units))
	}

	if len(res.Units) == 0 {
		if loggerD.Enabled() {
			loggerD.Info("No policy applies to this pod",
				"pod", peer.Pod.Name, "namespace", peer.Pod.Namespace, "labels", peer.Labels)
		}
		return defaultPassThrough, nil
	}

	// Record the resolved units only after the early returns, so a resolution
	// that yields nothing cannot erase a previous one. The stream logger was
	// already installed above, before the resolve error was honoured.
	state.units = res.Units

	// End-of-stream headers can synchronously resume an empty-body continuation,
	// but both engine entries still answer one Envoy ProcessingRequest. Give
	// them one outer deadline so the body phase cannot refresh the message budget.
	evalCtx := ctx
	cancel := func() {}
	if headers.GetEndOfStream() && s.pluginBudget > 0 {
		evalCtx, cancel = context.WithTimeout(ctx, s.pluginBudget)
	}
	defer cancel()

	er, evalErr := s.eng.EvalRequestHeaders(evalCtx, st, state.engineUnits())
	if evalErr != nil {
		return nil, evalErr
	}
	if er.NeedsBody() && headers.GetEndOfStream() {
		br, bodyErr := s.eng.EvalRequestBody(evalCtx, st, er, filter.Body{Complete: true})
		if bodyErr != nil {
			return nil, bodyErr
		}
		er = mergeBodylessRequestResults(er, br)
	}

	responses := translateRequestHeadersResult(er, loggerD, peer)
	if er.Disposition == engine.DispositionBlocked ||
		er.Disposition == engine.DispositionBypassed {
		state.finalizeAfterSend = true
	}

	// Assemble the single headers-phase ModeOverride. mode_override is only
	// accepted on header-phase responses, and each override must restate
	// both body modes: the merge base is the static config, so a missing
	// mode silently becomes NONE.
	if er.Disposition != engine.DispositionBlocked {
		wantBody := er.NeedsBody()
		observeResponse := s.observeResponses && er.Disposition != engine.DispositionBypassed
		if wantBody || observeResponse {
			override := &extProcV3.ProcessingMode{
				RequestBodyMode:  extProcV3.ProcessingMode_NONE,
				ResponseBodyMode: extProcV3.ProcessingMode_NONE,
			}
			if wantBody {
				override.RequestBodyMode = requestBodyMode
			}
			if observeResponse {
				override.ResponseHeaderMode = extProcV3.ProcessingMode_SEND
			}
			resp := cloneResponse(responses[0])
			resp.ModeOverride = override
			responses = append([]*extProcPb.ProcessingResponse{resp}, responses[1:]...)
		}
		if wantBody {
			state.eval = er
			state.awaitRequestBody = true
		}
		if observeResponse {
			state.awaitResponseHeaders = true
		}
	}
	return responses, nil
}

// mergeBodylessRequestResults renders the resumed empty-body continuation in
// the current request-headers phase. Header operations are folded again across
// the phase boundary because Envoy applies removals before sets within one
// HeaderMutation, and the later continuation must retain normal last-writer
// semantics.
func mergeBodylessRequestResults(er *engine.RequestHeadersResult, br *engine.RequestBodyResult) *engine.RequestHeadersResult {
	headerOps := engine.Fold([]filter.Mutation{
		{HeaderOps: er.HeaderOps},
		{HeaderOps: br.HeaderOps},
	})
	body := er.Body
	if br.Body != nil {
		body = br.Body
	}
	disposition := br.Disposition
	if disposition == engine.DispositionPassthrough &&
		(er.Disposition == engine.DispositionMutated || len(headerOps) > 0 || body != nil) {
		disposition = engine.DispositionMutated
	}
	return &engine.RequestHeadersResult{
		Disposition:     disposition,
		Reply:           br.Reply,
		HeaderOps:       headerOps,
		ClearRouteCache: er.ClearRouteCache || br.ClearRouteCache,
		Body:            body,
	}
}

// HandleResponseHeaders records the upstream status into the stream and
// dispatches the response-headers phase.
func (s *Server) HandleResponseHeaders(ctx context.Context, headers *extProcPb.HttpHeaders, state *streamState) ([]*extProcPb.ProcessingResponse, error) {
	if state == nil || !state.sawRequest {
		return nil, status.Error(codes.FailedPrecondition,
			"received response headers before request headers")
	}
	if state.responseHeadersSeen {
		return nil, status.Error(codes.FailedPrecondition, "received duplicate response headers")
	}
	if headers == nil || headers.GetHeaders() == nil {
		return nil, status.Error(codes.InvalidArgument, "response headers are missing")
	}
	state.responseHeadersSeen = true

	response := []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extProcPb.HeadersResponse{},
			},
		},
	}
	if state.finalized {
		// A static response-header mode can outlive a terminal request decision.
		// Acknowledge the first valid message without reopening observers or audit.
		state.awaitResponseHeaders = false
		return response, nil
	}

	respHeaders := make(map[string]string, len(headers.GetHeaders().GetHeaders()))
	responseStatus := 0
	for _, h := range headers.GetHeaders().GetHeaders() {
		key := strings.ToLower(h.Key)
		value := string(h.RawValue)
		respHeaders[key] = value
		if key == ":status" {
			if code, err := strconv.Atoi(value); err == nil {
				responseStatus = code
			}
		}
	}
	state.stream.Response = httpreq.HTTPResponse{Status: responseStatus, Headers: respHeaders}
	if err := s.eng.EvalResponseHeaders(ctx, state.stream, state.engineUnits()); err != nil {
		return nil, err
	}
	state.awaitResponseHeaders = false
	state.finalizeAfterSend = true
	return response, nil
}

// cloneResponse copies a ProcessingResponse so ModeOverride can be set
// without mutating package-level singletons (e.g. defaultPassThrough).
// proto.Clone is used because proto messages embed internal state that must
// not be copied by assignment.
func cloneResponse(r *extProcPb.ProcessingResponse) *extProcPb.ProcessingResponse {
	return proto.Clone(r).(*extProcPb.ProcessingResponse)
}

// extractRequestID returns the x-request-id header value, or "" when the
// header is absent. Envoy normalizes header names to lowercase, but the
// comparison is case-insensitive to stay robust against non-Envoy callers
// (e.g. unit tests).
func extractRequestID(headers *extProcPb.HttpHeaders) string {
	if headers == nil || headers.GetHeaders() == nil {
		return ""
	}
	for _, h := range headers.GetHeaders().GetHeaders() {
		if strings.EqualFold(h.Key, headerRequestID) {
			return string(h.RawValue)
		}
	}
	return ""
}

// defaultPassThrough is the shared passthrough response returned when no
// filter produces mutations. It is immutable and safe to share across
// goroutines — gRPC serializes but does not mutate the proto.
var defaultPassThrough = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extProcPb.HeadersResponse{},
	}},
}

// HandleRequestTrailers returns an empty pass-through response.
func (s *Server) HandleRequestTrailers(ctx context.Context, trailers *extProcPb.HttpTrailers) ([]*extProcPb.ProcessingResponse, error) {
	return []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extProcPb.TrailersResponse{},
			},
		},
	}, nil
}

// HandleResponseBody returns an empty pass-through response.
func (s *Server) HandleResponseBody(ctx context.Context, body *extProcPb.HttpBody) ([]*extProcPb.ProcessingResponse, error) {
	return []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_ResponseBody{
				ResponseBody: &extProcPb.BodyResponse{},
			},
		},
	}, nil
}

// HandleResponseTrailers returns an empty pass-through response.
func (s *Server) HandleResponseTrailers(ctx context.Context, trailers *extProcPb.HttpTrailers) ([]*extProcPb.ProcessingResponse, error) {
	return []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extProcPb.TrailersResponse{},
			},
		},
	}, nil
}
