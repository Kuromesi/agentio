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

	// Ask before evaluating, not after. The walk may suspend waiting for a request
	// body, and this reply is the only one whose override can still open the
	// response-headers phase, so a subscription discovered by running a filter
	// arrives too late whenever an earlier rule paused. Deriving it from the matched
	// configs makes it independent of how far the walk got.
	//
	// Nothing is stored for the response phase: the same predicate is a pure
	// function of the units pinned on this stream, so EvalResponseHeaders
	// recomputes it and cannot disagree with what this reply promised.
	ruleWants, subErr := s.eng.WantsResponseHeaders(state.engineUnits())
	if subErr != nil {
		// A policy that asks for a phase the engine cannot open is malformed, not
		// a runtime fault. Failing here — before the walk — also keeps a malformed
		// policy from triggering the side effects an executed rule has, such as
		// tokentransform fetching a Secret and minting a credential.
		return nil, subErr
	}

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

	// Assemble this reply's ModeOverride. mode_override is only honoured on
	// header-phase replies, and every override must restate both body modes: Envoy
	// copies body modes unconditionally while treating a DEFAULT header or trailer
	// mode as unset, so a body mode left out silently becomes NONE.
	//
	// A blocked request opens nothing: after an ImmediateResponse Envoy marks
	// processing complete and ignores everything further. A ModeOverride must
	// also never share a reply with an ImmediateResponse, since Envoy applies
	// the override before dispatching the oneof.
	//
	// This is the only override the stream sends today, but not the only one it
	// could: the response-headers reply is also a header-phase reply, and its
	// override is what would open a response *body* phase. Adding that means a
	// second assembly site with the same restate-every-body-mode obligation, which
	// is the seam to extract when it happens — the two sites must not diverge on
	// which fields they restate. Deliberately not extracted now: there is one caller.
	//
	// Envoy can also refuse the override outright, for reasons invisible here:
	// allow_mode_override=false, send_body_without_waiting_for_header_response=true,
	// a FULL_DUPLEX_STREAMED body mode in the static config, or an
	// allowed_override_modes allow-list that excludes what we asked for. Every one of
	// those surfaces as a stream that ends while state.awaitResponseHeaders is still
	// set, which Process reports as an outstanding processing obligation.
	wantResponse := false
	if er.Disposition != engine.DispositionBlocked {
		// Per-rule subscription survives a Bypass: the bypassing rule's own
		// response operations still apply; bypass suppresses following rules, not
		// itself. Observation, by contrast, is a stream-level concern and a
		// bypassed stream deliberately opts out of it.
		observeResponse := s.observeResponses && er.Disposition != engine.DispositionBypassed
		wantResponse = ruleWants || observeResponse
		wantBody := er.NeedsBody()
		if wantBody || wantResponse {
			override := &extProcV3.ProcessingMode{
				RequestBodyMode:  extProcV3.ProcessingMode_NONE,
				ResponseBodyMode: extProcV3.ProcessingMode_NONE,
			}
			if wantBody {
				override.RequestBodyMode = requestBodyMode
			}
			if wantResponse {
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
		if wantResponse {
			state.awaitResponseHeaders = true
		}
	}

	// Finalization is armed only when nothing further is expected. A bypass that
	// opened the response-headers phase must not finalize here: the stream would
	// then answer Envoy's response-headers message with a bare ack and never run
	// the response phase, silently dropping the mutations the bypass preserves.
	// Mirrors the body phase's finalizeAfterSend = !state.awaitResponseHeaders.
	switch er.Disposition {
	case engine.DispositionBlocked:
		state.finalizeAfterSend = true
	case engine.DispositionBypassed:
		state.finalizeAfterSend = !state.awaitResponseHeaders
	}
	return responses, nil
}

// mergeBodylessRequestResults renders the resumed empty-body continuation in
// the current request-headers phase. Header operations are folded again across
// the phase boundary because Envoy applies removals before sets within one
// HeaderMutation, and the later continuation must retain normal last-writer
// semantics.
//
// It carries no response-headers subscription: that is derived from the matched
// configs by Engine.Subscribe before either phase runs, so neither phase's result
// can add to or drop from it.
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

	if state.finalized {
		// A static response-header mode can outlive a terminal request decision.
		// Acknowledge the first valid message without reopening observers or audit.
		state.awaitResponseHeaders = false
		return emptyResponseHeadersAck, nil
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
	// Dispatch is driven by which configs subscribed, never by what opened the
	// phase: --observe-responses may have opened it so the stream loggers see the
	// upstream status, and no rule is invoked in that case. The engine recomputes
	// that predicate from the units pinned on this stream, which is the same input
	// the headers-phase ModeOverride was decided from. It bounds itself with the
	// plugin budget, so no outer deadline is added here.
	rr, evalErr := s.eng.EvalResponseHeaders(ctx, state.stream, state.engineUnits())
	if evalErr != nil {
		if rr.Disposition == engine.DispositionBlocked {
			// A synthesised FailClosed deny is a decision, and Envoy holds the
			// upstream headers only until we answer, so it must reach the wire.
			// Process sends it and still terminates the stream on the error.
			return translateResponseHeadersResult(rr), evalErr
		}
		// Every other error is a fault, not a decision, and leaves a zero-value
		// passthrough result — a filter returning Stop from the response phase,
		// say. Translating that emits a bare ack, which releases the UNMUTATED
		// upstream response downstream and only then tears the stream down: a
		// fail-open wearing an error's clothes. Send nothing and let Envoy's
		// failure_mode_allow make that call, as it did before this phase could
		// carry mutations.
		return nil, evalErr
	}
	state.awaitResponseHeaders = false
	state.finalizeAfterSend = true
	return translateResponseHeadersResult(rr), nil
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
