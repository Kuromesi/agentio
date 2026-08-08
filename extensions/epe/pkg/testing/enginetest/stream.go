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

package enginetest

import (
	"context"
	"io"
	"sync"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

// ScriptedStream implements extProcPb.ExternalProcessor_ProcessServer over a
// pre-built message script. Recv pops messages in order and returns io.EOF
// when the script is exhausted; Send records responses. Because Process is a
// single synchronous loop, tests call Server.Process(stream) directly on the
// test goroutine — no goroutines, no channels, fully deterministic.
//
// grpc.ServerStream is embedded as a nil interface on purpose: Process only
// uses Recv, Send, and Context. Any other stream method panics.
type ScriptedStream struct {
	grpc.ServerStream

	ctx context.Context

	mu    sync.Mutex
	input []*extProcPb.ProcessingRequest
	pos   int
	sent  []*extProcPb.ProcessingResponse

	// StopOnImmediate mimics Envoy: after an ImmediateResponse has been
	// sent, Recv returns io.EOF even if scripted messages remain. Enabled
	// by NewScriptedStream.
	StopOnImmediate bool
	// RecvErr, when set, is returned by Recv once the script is exhausted,
	// instead of io.EOF (exercises the codes.Unknown receive path).
	RecvErr error
	// SendErr, when set, is returned by the next Send call.
	SendErr error

	immediate bool
}

// NewScriptedStream builds a stream that will replay msgs in order.
func NewScriptedStream(ctx context.Context, msgs ...*extProcPb.ProcessingRequest) *ScriptedStream {
	return &ScriptedStream{
		ctx:             ctx,
		input:           msgs,
		StopOnImmediate: true,
	}
}

func (s *ScriptedStream) Context() context.Context {
	return s.ctx
}

func (s *ScriptedStream) Recv() (*extProcPb.ProcessingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.StopOnImmediate && s.immediate {
		return nil, io.EOF
	}
	if s.pos >= len(s.input) {
		if s.RecvErr != nil {
			return nil, s.RecvErr
		}
		return nil, io.EOF
	}
	msg := s.input[s.pos]
	s.pos++
	return msg, nil
}

func (s *ScriptedStream) Send(resp *extProcPb.ProcessingResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.SendErr != nil {
		err := s.SendErr
		s.SendErr = nil
		return err
	}
	s.sent = append(s.sent, resp)
	if _, ok := resp.GetResponse().(*extProcPb.ProcessingResponse_ImmediateResponse); ok {
		s.immediate = true
	}
	return nil
}

// Responses returns a snapshot of every response sent so far.
func (s *ScriptedStream) Responses() []*extProcPb.ProcessingResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*extProcPb.ProcessingResponse, len(s.sent))
	copy(out, s.sent)
	return out
}
