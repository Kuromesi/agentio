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
	"context"
	"encoding/json"
	"reflect"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc"
	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

func TestScenario_RequestHeaderMutationsReachExtProcWire(t *testing.T) {
	server := newWireServer(t, `{
		"request": {
			"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}],
			"add":[{"name":"X-Pod","value":"{{ .Pod.Name }}"}],
			"remove":["X-Legacy"]
		}
	}`)
	msgs := enginetest.NewRequest("GET", "api.example.com", "/v1/items").
		Header("X-Legacy", "old").
		Peer("default", "sandbox-a", map[string]string{"app": "demo"}).
		Build()

	stream := enginetest.NewScriptedStream(t.Context(), msgs...)
	processErr := server.Process(stream)
	verdict := enginetest.ParseVerdict(stream.Responses(), processErr)
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	want := []enginetest.HeaderOp{
		{Kind: enginetest.HeaderSet, Name: "x-policy", Value: "outbound"},
		{Kind: enginetest.HeaderAppend, Name: "x-pod", Value: "sandbox-a"},
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
	server := newWireServer(t, `{
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

	stream := enginetest.NewScriptedStream(t.Context(), msgs...)
	processErr := server.Process(stream)
	verdict := enginetest.ParseVerdict(stream.Responses(), processErr)
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
		{Kind: enginetest.HeaderAppend, Name: "set-cookie", Value: "trace=abc123"},
		{Kind: enginetest.HeaderRemove, Name: "server"},
	}
	if !reflect.DeepEqual(verdict.ResponseHeaderOps, want) {
		t.Errorf("ResponseHeaderOps = %+v, want %+v", verdict.ResponseHeaderOps, want)
	}
	if verdict.Kind != enginetest.VerdictPassthrough {
		t.Errorf("Kind = %s, want passthrough for a response-only mutation", verdict.Kind)
	}
}

func newWireServer(t *testing.T, payload string) *extproc.Server {
	t.Helper()
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		t.Fatalf("build registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		headermutation.FilterName: json.RawMessage(payload),
	})
	if errs[0] != nil {
		t.Fatalf("project payload: %v", errs[0])
	}
	resolve := func(_ context.Context, pod inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		scope := inputs.NewScope(
			inputs.RequestFrom(*req), pod,
			inputs.Profile{Name: "outbound", Namespace: "default"},
			inputs.Rule{Name: "mutate-headers"}, nil,
		)
		return engine.Resolution{Units: []engine.Unit{{
			ID:    filter.UnitID{Scope: "default/outbound", Name: "mutate-headers"},
			Scope: scope,
			Cfgs:  cfgs,
		}}}, nil
	}
	return extproc.NewServer(extproc.ServerDeps{
		Resolve:       resolve,
		Registrations: regs,
	})
}
