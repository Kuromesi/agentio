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
package httpcallout

import (
	"context"
	"fmt"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// Filter delegates one rule's enabled phases to the configured endpoint.
//
// It holds no phase state. The engine builds a fresh Filter per direction
// (eval.go calls reg.New inside each walk), so nothing could cross from the
// request phase to the response phase anyway, and the body callbacks are only
// invoked on the instance that returned NeedBody. cfg.Request and cfg.Response
// are therefore the only guards needed.
type Filter struct {
	filter.PassThrough
	cfg    Config
	id     filter.UnitID
	client Client
}

// NewDescriptor declares httpcallout to the framework. Every phase is declared
// because one Config may enable either direction; which ones actually run is
// decided per config by SubscribesOf and the guards below.
func NewDescriptor(deps Deps) filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name: FilterName,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody |
			filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		// Inverted from tokentransform: a callout is a security control, so the
		// safe default is to deny when it cannot be consulted, and FailOpen is
		// the explicit opt-out.
		OnError: func(cfg Config) filter.FailurePolicy {
			if cfg.FailOpen {
				return filter.FailOpen
			}
			return filter.FailClosed
		},
		// Not optional: without it the response walk skips this pair entirely
		// and the response half never runs. Returning 0 for a request-only
		// config is equally load-bearing — it keeps those requests from paying
		// ResponseHeaderMode SEND for a phase that would do nothing.
		SubscribesOf: func(cfg Config) filter.Phase {
			if !cfg.Response {
				return 0
			}
			return filter.PhaseResponseHeaders
		},
		New: func(rule filter.RuleConfig[Config]) filter.Filter {
			return &Filter{cfg: rule.Cfg, id: rule.ID, client: deps.Client}
		},
	}
}

// OnRequestHeaders defers to the body: a callout inspecting a request needs the
// whole message, and the invocation contract carries the body explicitly.
func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if !f.cfg.Request {
		return filter.Continue(), nil
	}
	return filter.NeedBody(), nil
}

// OnResponseHeaders defers to the response body for the same reason.
func (f *Filter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if !f.cfg.Response {
		return filter.Continue(), nil
	}
	return filter.NeedBody(), nil
}

// OnRequestBody performs the request-phase callout.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if !f.cfg.Request {
		return filter.Continue(), nil
	}
	inv, err := buildRequestInvocation(f.cfg, f.id, st, body)
	if err != nil {
		return filter.Action{}, err
	}
	return f.callout(ctx, PhaseRequest, inv)
}

// OnResponseBody performs the response-phase callout.
func (f *Filter) OnResponseBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if !f.cfg.Response {
		return filter.Continue(), nil
	}
	inv, err := buildResponseInvocation(f.cfg, f.id, st, body)
	if err != nil {
		return filter.Action{}, err
	}
	return f.callout(ctx, PhaseResponse, inv)
}

// callout sends one invocation and translates the answer. Every failure is
// returned as an error so the framework's OnError policy resolves it; this
// filter never hand-builds a deny, which is also what keeps the endpoint URL and
// the remote's text out of anything the client can see.
func (f *Filter) callout(ctx context.Context, phase Phase, inv Invocation) (filter.Action, error) {
	// Validate what EPE built before spending a network round trip on it: a
	// malformed invocation is an EPE bug, and the endpoint's rejection of it
	// would be a far less specific error.
	if err := inv.Validate(); err != nil {
		return filter.Action{}, err
	}
	if f.client == nil {
		return filter.Action{}, fmt.Errorf("callout client is not configured")
	}
	decision, err := f.client.Call(ctx, f.cfg, inv)
	if err != nil {
		// Wrapping names the phase for the log; the client already scrubbed the
		// endpoint out, and the client never sees this text because the
		// framework generates the deny from OnError.
		return filter.Action{}, fmt.Errorf("%s-phase callout failed: %w", phase, err)
	}
	// Validate against this invocation, not in isolation: that is what ties the
	// answer to the exchange it claims to answer.
	if err := decision.Validate(inv); err != nil {
		return filter.Action{}, err
	}
	return decisionAction(phase, decision)
}
