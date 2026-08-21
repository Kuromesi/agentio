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
package headermutation_test

import (
	"reflect"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

// Scenario tests drive the real extproc.Server over a scripted Envoy stream, so
// they assert on the proto responses that actually reach Envoy. The engine-level
// half — projection and evaluation with no wire — is projection_test.go.

func TestScenario_RequestHeaderMutationsReachExtProcWire(t *testing.T) {
	h := newWireHarness(t, `{
		"request": {
			"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}],
			"add":[{"name":"X-Pod","value":"{{ .Pod.Name }}"}],
			"remove":["X-Legacy"]
		}
	}`)
	verdict := h.Run(t, enginetest.NewRequest("GET", "api.example.com", "/v1/items").
		Header("X-Legacy", "old").
		Peer("default", "sandbox-a", map[string]string{"app": "demo"}))
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	want := []enginetest.HeaderOp{
		{Kind: enginetest.HeaderSet, Name: "x-policy", Value: "outbound"},
		{Kind: enginetest.HeaderAdd, Name: "x-pod", Value: "sandbox-a"},
		{Kind: enginetest.HeaderRemove, Name: "x-legacy"},
	}
	if !reflect.DeepEqual(verdict.RequestHeaderOps, want) {
		t.Errorf("RequestHeaderOps = %+v, want %+v", verdict.RequestHeaderOps, want)
	}
	if verdict.Kind != enginetest.VerdictMutated {
		t.Errorf("Kind = %s, want mutated", verdict.Kind)
	}
	if verdict.ModeOverride != nil {
		t.Errorf("ModeOverride = %v, want nil for request-only mutations", verdict.ModeOverride)
	}
}

func TestScenario_ResponseHeaderMutationsReachExtProcWire(t *testing.T) {
	h := newWireHarness(t, `{
		"response": {
			"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}],
			"add":[{"name":"Set-Cookie","value":"trace={{ .Request.Header \"X-Trace\" }}"}],
			"remove":["Server"]
		}
	}`)
	msgs := enginetest.NewRequest("GET", "api.example.com", "/v1/items").
		Header("X-Trace", "abc123").
		Peer("default", "sandbox-a", map[string]string{"app": "demo"}).
		Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extProcPb.HttpHeaders{
				Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
					{Key: ":status", RawValue: []byte("200")},
					{Key: "server", RawValue: []byte("upstream")},
				}},
			},
		},
	})

	verdict := h.RunMessages(t, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	if verdict.ModeOverride == nil || verdict.ModeOverride.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want ResponseHeaderMode SEND", verdict.ModeOverride)
	}
	if len(verdict.RequestHeaderOps) != 0 {
		t.Errorf("RequestHeaderOps = %+v, want none for response-only mutations", verdict.RequestHeaderOps)
	}
	want := []enginetest.HeaderOp{
		{Kind: enginetest.HeaderSet, Name: "x-policy", Value: "outbound"},
		{Kind: enginetest.HeaderAdd, Name: "set-cookie", Value: "trace=abc123"},
		{Kind: enginetest.HeaderRemove, Name: "server"},
	}
	if !reflect.DeepEqual(verdict.ResponseHeaderOps, want) {
		t.Errorf("ResponseHeaderOps = %+v, want %+v", verdict.ResponseHeaderOps, want)
	}
	if verdict.Kind != enginetest.VerdictPassthrough {
		t.Errorf("Kind = %s, want passthrough for a response-only mutation", verdict.Kind)
	}
}

func newWireHarness(t *testing.T, payload string) *enginetest.Harness {
	t.Helper()
	return enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: headermutation.Definition(),
		Payload:    payload,
		Profile:    inputs.Profile{Name: "outbound", Namespace: "default"},
		Rule:       inputs.Rule{Name: "mutate-headers"},
	})
}
