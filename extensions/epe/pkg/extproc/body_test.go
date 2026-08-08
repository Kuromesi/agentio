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

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

func TestHandleRequestBody_PassthroughByDefault(t *testing.T) {
	s := NewServer(ServerDeps{})
	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{Body: []byte("x"), EndOfStream: true}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected non-empty passthrough response")
	}
	if res[0].GetRequestBody() == nil {
		t.Fatalf("expected RequestBody response variant, got %T", res[0].Response)
	}
}

func TestHandleRequestBody_NoPendingEval(t *testing.T) {
	s := NewServer(ServerDeps{})
	state := newStreamState()
	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{Body: []byte("x"), EndOfStream: true}, state)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res[0].GetRequestBody() == nil {
		t.Fatalf("expected passthrough body response")
	}
}

func TestHandleRequestBody_SetsBodyAndRunsBodyPhase(t *testing.T) {
	fp := &bodyProbe{bodyAct: filter.Continue(filter.SetHeader("x-test", "injected"))}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)

	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body: []byte("form-data"), EndOfStream: true,
	}, state)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Error("expected the body phase to run")
	}
	if string(fp.receivedBody) != "form-data" {
		t.Errorf("expected body 'form-data', got %q", fp.receivedBody)
	}
	if len(res) == 0 {
		t.Fatal("expected mutation response")
	}
	bodyResp := res[0].GetRequestBody()
	if bodyResp == nil {
		t.Fatalf("expected RequestBody response, got %T", res[0].Response)
	}
	hm := bodyResp.Response.GetHeaderMutation()
	if hm == nil || len(hm.SetHeaders) == 0 {
		t.Fatal("expected header mutation in body response")
	}
	if hm.SetHeaders[0].Header.Key != "x-test" {
		t.Errorf("expected header key x-test, got %s", hm.SetHeaders[0].Header.Key)
	}
	if string(hm.SetHeaders[0].Header.RawValue) != "injected" {
		t.Errorf("expected value 'injected', got %q", hm.SetHeaders[0].Header.RawValue)
	}
}

func TestHandleRequestBody_ConsumesPendingEvaluationOnce(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)
	state.awaitRequestBody = true

	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body: []byte("data"), EndOfStream: true,
	}, state); err != nil {
		t.Fatalf("first body: %v", err)
	}
	if state.eval != nil {
		t.Fatal("pending header evaluation was not cleared")
	}
	if state.awaitRequestBody {
		t.Fatal("request-body obligation was not consumed")
	}

	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body: []byte("duplicate"), EndOfStream: true,
	}, state); err != nil {
		t.Fatalf("duplicate body: %v", err)
	}
	if fp.bodyCalls != 1 {
		t.Fatalf("body phase ran %d times, want exactly once", fp.bodyCalls)
	}
}

func TestHandleRequestBody_ArmsOnlyTerminalFinalization(t *testing.T) {
	tests := []struct {
		name          string
		action        filter.Action
		awaitResponse bool
		wantFinalize  bool
	}{
		{
			name:         "blocked",
			action:       filter.Stop(filter.Reply{Status: 403}),
			wantFinalize: true,
		},
		{
			name:          "blocked retires response observation",
			action:        filter.Stop(filter.Reply{Status: 403}),
			awaitResponse: true,
			wantFinalize:  true,
		},
		{
			name:         "bypassed without response observation",
			action:       filter.Bypass(),
			wantFinalize: true,
		},
		{
			name:          "bypassed while awaiting response observation",
			action:        filter.Bypass(),
			awaitResponse: true,
			wantFinalize:  false,
		},
		{
			name:         "ordinary passthrough",
			action:       filter.Continue(),
			wantFinalize: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &bodyProbe{bodyAct: tt.action}
			s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)
			state.awaitRequestBody = true
			state.awaitResponseHeaders = tt.awaitResponse

			if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
				Body: []byte("data"), EndOfStream: true,
			}, state); err != nil {
				t.Fatalf("HandleRequestBody: %v", err)
			}
			if state.finalizeAfterSend != tt.wantFinalize {
				t.Fatalf("finalizeAfterSend = %v, want %v", state.finalizeAfterSend, tt.wantFinalize)
			}
			if tt.action.Kind() == filter.KindStop && state.awaitResponseHeaders {
				t.Fatal("blocked body result left an impossible response obligation")
			}
		})
	}
}

func TestHandleRequestBody_ContinueYieldsPassthrough(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)

	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body: []byte("data"), EndOfStream: true,
	}, state)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Error("expected the body phase to run")
	}
	if res[0].GetRequestBody() == nil {
		t.Fatalf("expected passthrough body response when the filter continues")
	}
}
