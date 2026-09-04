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

package enginetest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func TestHarnessRunsInjectedResolver(t *testing.T) {
	regs, err := filter.Build(block.Definition())
	if err != nil {
		t.Fatalf("build block registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		block.FilterName: json.RawMessage(`{"statusCode":451,"body":"blocked-neutral"}`),
	})
	if errs[0] != nil {
		t.Fatalf("project block payload: %v", errs[0])
	}
	resolve := func(_ context.Context, pod inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		return engine.Resolution{Units: []engine.Unit{{
			ID:    filter.UnitID{Scope: "test/profile", Name: "block"},
			Scope: inputs.NewScope(inputs.RequestFrom(*req), pod, inputs.Profile{}, inputs.Rule{}, nil),
			Cfgs:  cfgs,
		}}}, nil
	}

	h := New(t, Options{Resolve: resolve, Registrations: regs})
	h.Run(t, NewRequest("GET", "server.example.com", "/blocked").
		Peer("test", "pod", map[string]string{"app": "test"})).
		RequireBlockedBody(t, 451, "blocked-neutral")
}

// Verdict.AccessLog documents itself as the entries for one run, so a second
// Run must not still carry the first one's entry. Info is already scoped this
// way; the audit log has to agree, or every outcome assertion on the second
// request in a test reads an entry from the first.
func TestHarness_AccessLogIsScopedToOneRun(t *testing.T) {
	resolve := func(_ context.Context, _ inputs.Pod, _ *httpreq.HTTPRequest) (engine.Resolution, error) {
		return engine.Resolution{}, nil
	}
	h := New(t, Options{Resolve: resolve})
	req := func() *RequestBuilder {
		return NewRequest("GET", "server.example.com", "/x").
			Peer("test", "pod", map[string]string{"app": "test"})
	}

	if got := h.Run(t, req()); len(got.AccessLog) != 1 {
		t.Fatalf("first run AccessLog = %+v, want exactly 1 entry", got.AccessLog)
	}
	if got := h.Run(t, req()); len(got.AccessLog) != 1 {
		t.Fatalf("second run AccessLog = %+v, want only its own entry", got.AccessLog)
	}
}
