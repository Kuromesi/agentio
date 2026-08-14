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
	"encoding/json"
	"testing"

	"github.com/go-logr/logr"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// A headers-phase body mutation under plain CONTINUE is silently dropped
// by Envoy; the adapter must use CONTINUE_AND_REPLACE.
func TestTranslate_HeadersBodyMutationUsesContinueAndReplace(t *testing.T) {
	er := &engine.RequestHeadersResult{
		Disposition: engine.DispositionMutated,
		Body:        []byte("replaced"),
	}
	resp := translateRequestHeadersResult(er, logr.Discard(), filter.Peer{})
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetRequestHeaders().GetResponse()
	if common.GetStatus() != extProcPb.CommonResponse_CONTINUE_AND_REPLACE {
		t.Errorf("Status = %v, want CONTINUE_AND_REPLACE — plain CONTINUE drops body mutations", common.GetStatus())
	}
	if string(common.GetBodyMutation().GetBody()) != "replaced" {
		t.Errorf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
}

func TestTranslate_ResponseHeadersBodyMutationUsesContinueAndReplace(t *testing.T) {
	er := &engine.ResponseHeadersResult{
		Disposition: engine.DispositionMutated,
		HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-response", Value: "mutated"},
		},
		Body: []byte("replaced"),
	}
	resp := translateResponseHeadersResult(er)
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetResponseHeaders().GetResponse()
	if common.GetStatus() != extProcPb.CommonResponse_CONTINUE_AND_REPLACE {
		t.Errorf("Status = %v, want CONTINUE_AND_REPLACE", common.GetStatus())
	}
	if string(common.GetBodyMutation().GetBody()) != "replaced" {
		t.Errorf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	if len(common.GetHeaderMutation().GetSetHeaders()) != 1 {
		t.Errorf("HeaderMutation = %v, want the response header mutation preserved", common.GetHeaderMutation())
	}
}

// A BUFFERED body rewrite with a stale content-length is a hard 500; the
// adapter must set a matching content-length with the mutation.
func TestTranslate_BodyPhaseRewriteSetsContentLength(t *testing.T) {
	br := &engine.RequestBodyResult{
		Disposition: engine.DispositionMutated,
		Body:        []byte("new-body!"),
	}
	resp := translateRequestBodyResult(br)
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetRequestBody().GetResponse()
	if string(common.GetBodyMutation().GetBody()) != "new-body!" {
		t.Fatalf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	found := false
	for _, h := range common.GetHeaderMutation().GetSetHeaders() {
		if h.GetHeader().GetKey() == "content-length" {
			found = true
			if got := string(h.GetHeader().GetRawValue()); got != "9" {
				t.Errorf("content-length = %q, want 9", got)
			}
		}
	}
	if !found {
		t.Error("no content-length header set alongside the body rewrite")
	}
}

// A :path SET must force clear_route_cache even when the filter forgot the
// flag: an earlier filter's cached route would otherwise silently win.
func TestTranslate_PathOpForcesClearRouteCache(t *testing.T) {
	er := &engine.RequestHeadersResult{
		Disposition: engine.DispositionMutated,
		HeaderOps:   []filter.HeaderOp{{Kind: filter.HeaderSet, Name: ":path", Value: "/new"}},
		// ClearRouteCache deliberately false: the adapter must derive it.
	}
	resp := translateRequestHeadersResult(er, logr.Discard(), filter.Peer{})
	common := resp[0].GetRequestHeaders().GetResponse()
	if !common.GetClearRouteCache() {
		t.Error("clear_route_cache not set for a :path rewrite")
	}
}

// Engine-side: a filter's Mutation.Body flows into the result, last writer
// in execution order wins.
func TestEval_BodyMutationLastWriterWins(t *testing.T) {
	regA := fixedRegHeaders("a", filter.Continue(filter.Mutation{Body: []byte("one")}))
	regB := fixedRegHeaders("b", filter.Continue(filter.Mutation{Body: []byte("two")}))
	e := engine.NewEngine([]filter.Registration{regA, regB}, 0)
	units := []engine.Unit{{ID: filter.UnitID{Scope: "ns/p", Name: "r"}, Cfgs: []any{struct{}{}, struct{}{}}}}
	er, err := e.EvalRequestHeaders(t.Context(), &filter.Stream{}, units)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if er.Body == nil || string(er.Body) != "two" {
		t.Fatalf("Body = %q, want last writer 'two'", er.Body)
	}
	if er.Disposition != engine.DispositionMutated {
		t.Errorf("Disposition = %v, want Mutated", er.Disposition)
	}
}

func fixedRegHeaders(name string, act filter.Action) filter.Registration {
	return filter.Registration{
		Name:   name,
		Phases: filter.PhaseRequestHeaders,
		Parse:  func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New: func(filter.ErasedRuleConfig) filter.Filter {
			return &actionFilter{act: act}
		},
	}
}

type actionFilter struct {
	filter.PassThrough
	act filter.Action
}

func (f *actionFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.act, nil
}
