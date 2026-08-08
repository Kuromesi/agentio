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
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// A request carrying HTTP trailers makes Envoy flush the complete buffered
// body as one message with EndOfStream=false (ext_proc.cc onTrailers, "sending
// data left over in the buffer"). Trailer mode is SKIP, so no further body
// message follows. The verdict must be rendered on that message: withholding
// it until an EndOfStream that never comes acknowledges the body, and
// acknowledging releases it upstream unjudged.
func TestProcessRequestBody_TrailerFlushedBodyIsJudged(t *testing.T) {
	fp := &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 403})}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"denied"}}`)

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        body,
		EndOfStream: false,
	}, state, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Fatal("body phase never ran: the trailer-flushed body was released unjudged")
	}
	if string(fp.receivedBody) != string(body) {
		t.Errorf("body phase received %q, want the complete body %q", fp.receivedBody, body)
	}
	if len(resp) == 0 {
		t.Fatal("expected a response")
	}
	if resp[0].GetImmediateResponse() == nil {
		t.Fatalf("want the deny verdict as an ImmediateResponse, got %T", resp[0].Response)
	}
}

// While a body need is pending, no body message may be answered with a bare
// pass-through acknowledgement: acknowledging is what releases the bytes
// toward the upstream, so an ack without a verdict is a release without a
// verdict. This must hold whatever EndOfStream says.
func TestProcessRequestBody_PendingBodyNeedIsNeverAcknowledgedUnjudged(t *testing.T) {
	for _, eos := range []bool{false, true} {
		fp := &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 452})}
		s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
		logger := log.FromContext(context.Background())

		resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
			Body:        []byte(`{"jsonrpc":"2.0","method":"tools/call"}`),
			EndOfStream: eos,
		}, state, logger)
		if err != nil {
			t.Fatalf("endOfStream=%v: unexpected error: %v", eos, err)
		}
		if fp.bodyCalls != 1 {
			t.Fatalf("endOfStream=%v: body phase ran %d times, want exactly 1", eos, fp.bodyCalls)
		}
		if len(resp) != 1 {
			t.Fatalf("endOfStream=%v: want exactly one response, got %d", eos, len(resp))
		}
		if resp[0].GetImmediateResponse() == nil {
			t.Fatalf("endOfStream=%v: the filter's deny must reach Envoy, got %T", eos, resp[0].Response)
		}
	}
}

// A message shorter than the complete body is judged on what arrived rather
// than acknowledged. BUFFERED does not produce short messages, so this pins
// the fail-closed direction for the case where one somehow appears.
func TestProcessRequestBody_ShortBodyIsJudgedNotReleased(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	truncated := []byte(`{"jsonrpc":"2.0","met`)

	if _, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        truncated,
		EndOfStream: false,
	}, state, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls != 1 {
		t.Fatalf("body phase ran %d times, want exactly 1", fp.bodyCalls)
	}
	if string(fp.receivedBody) != string(truncated) {
		t.Errorf("body phase received %q, want %q", fp.receivedBody, truncated)
	}
}

// A single chunk with EndOfStream=true still works with body handlers
// present.
func TestProcessRequestBody_SingleChunk_NonStreamingServer(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	body := []byte(`{"complete":"body"}`)

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        body,
		EndOfStream: true,
	}, state, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Fatal("body phase should run on single-chunk EOS")
	}
	if string(fp.receivedBody) != string(body) {
		t.Errorf("body phase received %q, want %q", fp.receivedBody, body)
	}
	if len(resp) == 0 {
		t.Fatal("expected response")
	}
}

// When no filter needs the body, passthrough still works.
func TestProcessRequestBody_NoBodyHandlers(t *testing.T) {
	state := newStreamState()
	s := NewServer(ServerDeps{})
	logger := log.FromContext(context.Background())

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("data"),
		EndOfStream: true,
	}, state, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected passthrough response")
	}
	if resp[0].GetRequestBody() == nil {
		t.Fatalf("expected passthrough body response, got %T", resp[0].Response)
	}
}
