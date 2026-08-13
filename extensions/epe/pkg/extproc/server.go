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
	"errors"
	"fmt"
	"io"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/audit/accesslog"
	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/logging"
)

// Server implements the Envoy external processing server.
// https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto
type Server struct {
	observeResponses bool
	pluginBudget     time.Duration
	resolve          engine.Resolver
	eng              *engine.Engine
	loggers          []filter.StreamLogger
}

// ServerDeps holds the dependencies needed by the ext-proc server.
type ServerDeps struct {
	// Resolve maps request identity to applicable units. Required.
	Resolve engine.Resolver
	// Registrations is the action order applied inside every rule.
	Registrations []filter.Registration
	// AuditLogger receives one accesslog Entry per stream. May be nil in
	// tests; a no-op replaces it.
	AuditLogger accesslog.Logger
	// StreamLoggers are invoked once per stream, after the accesslog logger.
	// Terminal results commit after a successful response send; teardown and
	// error paths use fallback finalization.
	StreamLoggers []filter.StreamLogger
	// PluginBudget bounds all plugin work triggered by one ext_proc message.
	// Zero disables it.
	// Should be set below Envoy's message_timeout so the filter is
	// cancelled before Envoy gives up.
	PluginBudget time.Duration
	// ObserveResponses opens the response-headers phase via ModeOverride
	// so stream loggers can record the upstream status.
	ObserveResponses bool
}

// NewServer builds the ext-proc server from deps.
func NewServer(deps ServerDeps) *Server {
	loggers := []filter.StreamLogger{accesslog.NewStreamLog(deps.AuditLogger)}
	loggers = append(loggers, deps.StreamLoggers...)
	return &Server{
		observeResponses: deps.ObserveResponses,
		pluginBudget:     deps.PluginBudget,
		resolve:          deps.Resolve,
		eng:              engine.NewEngine(deps.Registrations, deps.PluginBudget),
		loggers:          loggers,
	}
}

// Process is the main gRPC streaming method for the external processor.
// It receives requests from Envoy, processes them, and sends back responses.
func (s *Server) Process(srv extProcPb.ExternalProcessor_ProcessServer) (retErr error) {
	ctx := srv.Context()
	logger := log.FromContext(ctx)
	loggerD := logger.V(logging.DEBUG)
	loggerD.Info("Processing request started")

	state := newStreamState()

	// The stream loggers fire exactly once. Finalized terminal responses do
	// not wait for physical stream end; this defer remains the fallback for
	// completion, per-message failure, Envoy reset, or ctx cancellation.
	// WithoutCancel: the first ctx-honoring logger would otherwise silently
	// no-op on precisely the teardown paths this exists for.
	defer func() {
		err := retErr
		if err == nil {
			err = ctx.Err()
		}
		s.finishStream(context.WithoutCancel(ctx), state, err)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, recvErr := srv.Recv()
		if recvErr == io.EOF {
			if state.awaitingInput() {
				return status.Error(codes.Unknown,
					"ext-proc stream ended with an outstanding processing obligation")
			}
			s.finishStream(context.WithoutCancel(ctx), state, nil)
			return nil
		}
		if errors.Is(recvErr, context.Canceled) || status.Code(recvErr) == codes.Canceled {
			// Envoy routinely resets the ext-proc stream instead of
			// half-closing once it needs nothing further, so cancellation
			// alone carries no error meaning. Only a cancel that truncates
			// an outstanding processing obligation is recorded as one.
			var finishErr error
			if state.awaitingInput() {
				finishErr = context.Canceled
			}
			s.finishStream(context.WithoutCancel(ctx), state, finishErr)
			return nil
		}
		if recvErr != nil {
			logger.V(logging.DEFAULT).Error(recvErr, "Cannot receive stream request")
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", recvErr)
		}

		var responses []*extProcPb.ProcessingResponse
		var err error
		switch v := req.Request.(type) {
		case *extProcPb.ProcessingRequest_RequestHeaders:
			responses, err = s.HandleRequestHeaders(ctx, req.GetRequestHeaders(), req.Attributes, state)
		case *extProcPb.ProcessingRequest_RequestBody:
			// Reuse the request ID captured during the headers phase so
			// body-phase logs (and downstream filters) share the same tag.
			bodyLogger := logger.WithValues(logKeyRequestID, state.stream.RequestID)
			bodyCtx := log.IntoContext(ctx, bodyLogger)
			if bodyLoggerD := bodyLogger.V(logging.DEBUG); bodyLoggerD.Enabled() {
				bodyLoggerD.Info("Incoming body chunk", "body", string(v.RequestBody.Body), "EoS", v.RequestBody.EndOfStream)
			}
			responses, err = s.processRequestBody(bodyCtx, req.GetRequestBody(), state, bodyLogger)
		case *extProcPb.ProcessingRequest_RequestTrailers:
			responses, err = s.HandleRequestTrailers(ctx, req.GetRequestTrailers())
		case *extProcPb.ProcessingRequest_ResponseHeaders:
			responses, err = s.HandleResponseHeaders(ctx, req.GetResponseHeaders(), state)
		case *extProcPb.ProcessingRequest_ResponseBody:
			responses, err = s.HandleResponseBody(ctx, req.GetResponseBody())
		case *extProcPb.ProcessingRequest_ResponseTrailers:
			responses, err = s.HandleResponseTrailers(ctx, req.GetResponseTrailers())
		default:
			// The Go type names which oneof arm arrived, which is what says
			// how processing modes are misconfigured. Its contents are not
			// logged, for the same reason the failure path below does not.
			logger.V(logging.DEFAULT).Error(nil, "Unknown Request type",
				"messageType", fmt.Sprintf("%T", v))
			return status.Error(codes.Unknown, "unknown request type")
		}

		if err != nil {
			// The failing message type is what triages this. The message itself
			// is not logged, at any level: request headers carry
			// x-agentio-sandbox-token, so dumping it wrote a live sandbox
			// credential into the log whenever debug was enabled.
			logger.V(logging.DEFAULT).Error(err, "Failed to process request",
				"messageType", messageTypeName(req))
			// A handler may pair its error with a reply that must still reach
			// Envoy — the response-headers phase under FailClosed synthesises an
			// ImmediateResponse that replaces the upstream response, and Envoy
			// holds those headers only until we answer. Erroring without sending
			// would fall back to Envoy's own failure_mode_allow handling and lose
			// the policy's status and details. Send failures are subordinate: the
			// original error is what terminates the stream.
			for _, resp := range responses {
				if sendErr := srv.Send(resp); sendErr != nil {
					logger.V(logging.DEFAULT).Error(sendErr, "Send failed while surfacing a handler error")
					break
				}
			}
			return status.Errorf(status.Code(err), "failed to handle request: %v", err)
		}

		for _, resp := range responses {
			if loggerD.Enabled() {
				// Header names but not values: a response carries the
				// credentials tokentransform injected, so the full message is as
				// sensitive as the request it answers.
				loggerD.Info("Response generated",
					"responseType", responseTypeName(resp),
					"setHeaders", mutatedHeaderNames(resp))
			}
			if err := srv.Send(resp); err != nil {
				logger.V(logging.DEFAULT).Error(err, "Send failed")
				return status.Errorf(codes.Unknown, "failed to send response back to Envoy: %v", err)
			}
		}
		s.finishAfterSend(ctx, state)
	}
}

// finishStream invokes the stream loggers exactly once per stream, after a
// request was actually observed. Idempotent: the first caller wins.
func (s *Server) finishStream(ctx context.Context, state *streamState, err error) {
	if state == nil || !state.sawRequest || state.finalized {
		return
	}
	state.finalized = true
	info := state.stream.Info
	if err != nil {
		info.Error = err.Error()
		info.Promote(filter.DispositionError)
	}
	for _, l := range s.loggers {
		l.Log(ctx, state.stream, info)
	}
	// The resolver's per-stream logger runs last: after the static list, and
	// after the error promotion above, so it observes the final disposition.
	if state.streamLogger != nil {
		state.streamLogger.Log(ctx, state.stream, info)
	}
}

// finishAfterSend commits a pending finalization only after Envoy accepted the
// complete response slice for the current processing request.
func (s *Server) finishAfterSend(ctx context.Context, state *streamState) {
	if state == nil || !state.finalizeAfterSend {
		return
	}
	state.finalizeAfterSend = false
	s.finishStream(context.WithoutCancel(ctx), state, nil)
}

// streamState carries per-stream state between the phases: the Stream and
// its StreamInfo (owned by this stream, written by the engine), the
// resolved policy units, and the pending body-phase eval.
type streamState struct {
	stream *filter.Stream
	units  []engine.Unit
	// streamLogger is the per-stream logger the resolver supplied, if any.
	// It is assigned alongside units and for the same reason: both describe
	// the resolution that took effect, so a later resolution returning
	// nothing must leave both untouched rather than clear them.
	streamLogger filter.StreamLogger
	eval         *engine.RequestHeadersResult
	// sawRequest is set once request headers were processed, so streams
	// that never carried a request do not produce empty log entries.
	sawRequest           bool
	finalized            bool
	awaitRequestBody     bool
	awaitResponseHeaders bool
	responseHeadersSeen  bool
	finalizeAfterSend    bool
}

func newStreamState() *streamState {
	return &streamState{
		stream: &filter.Stream{Info: filter.NewStreamInfo()},
	}
}

// engineUnits returns the engine-facing units; the resolver already hands
// them over in neutral form.
func (st *streamState) engineUnits() []engine.Unit { return st.units }

func (st *streamState) awaitingInput() bool {
	return st != nil && (st.awaitRequestBody || st.awaitResponseHeaders)
}

// processRequestBody runs the body phase on the message Envoy delivered.
//
// A body message always carries the complete body. The headers phase pins
// ModeOverride to BUFFERED, and BUFFERED emits the whole body at once: either
// with EndOfStream set, or — when the request carries HTTP trailers — as the
// leftover-buffer flush Envoy sends from onTrailers with EndOfStream clear.
// Envoy never splits a body across messages in that mode.
//
// EndOfStream therefore deliberately does not gate the dispatch. Waiting for
// an end-of-stream message that a trailer-carrying request never sends would
// acknowledge the body instead, and acknowledging is what releases it toward
// the upstream — the verdict would go unrendered on bytes already gone.
// Judging what arrived is also the safe reading if a short message ever shows
// up: the filters decide on a truncated body rather than letting it pass.
func (s *Server) processRequestBody(ctx context.Context, body *extProcPb.HttpBody, state *streamState, logger logr.Logger) ([]*extProcPb.ProcessingResponse, error) {
	logger.V(logging.DEBUG).Info("Dispatching request body",
		"bytes", len(body.GetBody()), "endOfStream", body.EndOfStream)

	return s.HandleRequestBody(ctx, body, state)
}

// messageTypeName names an ext_proc request message without rendering it. The
// message is never logged: request headers carry x-agentio-sandbox-token, and a
// body carries whatever the caller sent.
func messageTypeName(req *extProcPb.ProcessingRequest) string {
	switch req.GetRequest().(type) {
	case *extProcPb.ProcessingRequest_RequestHeaders:
		return "request_headers"
	case *extProcPb.ProcessingRequest_RequestBody:
		return "request_body"
	case *extProcPb.ProcessingRequest_RequestTrailers:
		return "request_trailers"
	case *extProcPb.ProcessingRequest_ResponseHeaders:
		return "response_headers"
	case *extProcPb.ProcessingRequest_ResponseBody:
		return "response_body"
	case *extProcPb.ProcessingRequest_ResponseTrailers:
		return "response_trailers"
	default:
		return "unknown"
	}
}

// responseTypeName names an ext_proc response message, for the same reason.
func responseTypeName(resp *extProcPb.ProcessingResponse) string {
	switch resp.GetResponse().(type) {
	case *extProcPb.ProcessingResponse_RequestHeaders:
		return "request_headers"
	case *extProcPb.ProcessingResponse_RequestBody:
		return "request_body"
	case *extProcPb.ProcessingResponse_RequestTrailers:
		return "request_trailers"
	case *extProcPb.ProcessingResponse_ResponseHeaders:
		return "response_headers"
	case *extProcPb.ProcessingResponse_ResponseBody:
		return "response_body"
	case *extProcPb.ProcessingResponse_ResponseTrailers:
		return "response_trailers"
	case *extProcPb.ProcessingResponse_ImmediateResponse:
		return "immediate"
	default:
		return "unknown"
	}
}

// mutatedHeaderNames lists the header names a response sets or removes, so a
// debug log can show which mutations were rendered. Values are omitted on
// purpose: the credential tokentransform injects is one of them, and an
// immediate response's headers are attacker-visible policy output.
func mutatedHeaderNames(resp *extProcPb.ProcessingResponse) []string {
	var mut *extProcPb.HeaderMutation
	switch r := resp.GetResponse().(type) {
	case *extProcPb.ProcessingResponse_RequestHeaders:
		mut = r.RequestHeaders.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_RequestBody:
		mut = r.RequestBody.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_ResponseHeaders:
		mut = r.ResponseHeaders.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_ImmediateResponse:
		mut = r.ImmediateResponse.GetHeaders()
	}
	if mut == nil {
		return nil
	}
	names := make([]string, 0, len(mut.GetSetHeaders())+len(mut.GetRemoveHeaders()))
	for _, h := range mut.GetSetHeaders() {
		names = append(names, h.GetHeader().GetKey())
	}
	return append(names, mut.GetRemoveHeaders()...)
}
