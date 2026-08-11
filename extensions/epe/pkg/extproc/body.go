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

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/logging"
)

// defaultPassThroughBody is the empty-mutation body response.
var defaultPassThroughBody = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestBody{
		RequestBody: &extProcPb.BodyResponse{},
	}},
}

// HandleRequestBody handles the complete request body delivered by Envoy
// after the headers phase set ModeOverride to BUFFERED. It resumes the
// paused rule/action cursor. When no filter needs the body (state is nil or
// carries no pending eval), it returns a passthrough.
func (s *Server) HandleRequestBody(ctx context.Context, body *extProcPb.HttpBody, state *streamState) ([]*extProcPb.ProcessingResponse, error) {
	if state == nil || state.eval == nil || !state.eval.NeedsBody() {
		return defaultPassThroughBody, nil
	}

	loggerD := log.FromContext(ctx).V(logging.DEBUG)
	loggerD.Info("Running deferred body-phase filters", "bodyLen", len(body.Body))

	prior := state.eval
	state.eval = nil
	state.awaitRequestBody = false
	br, err := s.eng.EvalRequestBody(ctx, state.stream, prior, filter.Body{
		Bytes: body.Body,
		// Deliberately not body.EndOfStream. BUFFERED — the only body mode the
		// headers phase requests — delivers the whole body in one message, and
		// the trailer-flush variant delivers it with EndOfStream clear. Copying
		// the flag would tell filters that a complete body was partial.
		Complete: true,
	})
	if err != nil {
		return nil, err
	}
	switch br.Disposition {
	case engine.DispositionBlocked:
		state.awaitResponseHeaders = false
		state.finalizeAfterSend = true
	case engine.DispositionBypassed:
		state.finalizeAfterSend = !state.awaitResponseHeaders
	}
	return translateRequestBodyResult(br), nil
}
