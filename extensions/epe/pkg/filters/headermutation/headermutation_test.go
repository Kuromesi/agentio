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
package headermutation

import (
	"context"
	"encoding/json"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestFilterRendersHeaderMutations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"request": {
			"set": [
				{"name": "X-Tenant", "value": "{{ .Pod.Namespace }}:{{ .Request.Header \"X-Source\" }}"},
				{"name": "X-Policy", "value": "{{ .Profile.Name }}/{{ .Rule.Name }}"}
			],
			"add": [{"name": "X-Tag", "value": "{{ index .Inputs \"tag\" }}"}],
			"remove": ["X-Legacy"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	scope := inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{Headers: map[string]string{"x-source": "sandbox"}}),
		inputs.Pod{Namespace: "payments"},
		inputs.Profile{Name: "outbound", Namespace: "payments"},
		inputs.Rule{Name: "inject-context"},
		map[string]any{"tag": "trusted"},
	)
	f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: scope})

	got, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	want := filter.Continue(
		filter.SetHeader("x-tenant", "payments:sandbox"),
		filter.SetHeader("x-policy", "outbound/inject-context"),
		filter.AppendHeader("x-tag", "trusted"),
		filter.RemoveHeader("x-legacy"),
	)
	if !got.Equal(want) {
		t.Errorf("action = %+v, want rendered set/add/remove mutations", got)
	}
}

func TestFilterRendersResponseHeaderMutations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"response": {
			"set": [{"name": "X-Policy", "value": "{{ .Profile.Name }}/{{ .Rule.Name }}"}],
			"add": [{"name": "X-Tag", "value": "{{ index .Inputs \"tag\" }}"}],
			"remove": ["Server"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
		inputs.Request{},
		inputs.Pod{Namespace: "payments"},
		inputs.Profile{Name: "outbound"},
		inputs.Rule{Name: "inject-context"},
		map[string]any{"tag": "trusted"},
	)})

	got, err := f.OnResponseHeaders(context.Background(), &filter.Stream{})
	if err != nil {
		t.Fatalf("OnResponseHeaders: %v", err)
	}
	want := filter.Continue(
		filter.SetHeader("x-policy", "outbound/inject-context"),
		filter.AppendHeader("x-tag", "trusted"),
		filter.RemoveHeader("server"),
	)
	if !got.Equal(want) {
		t.Errorf("action = %+v, want rendered response set/add/remove mutations", got)
	}
}

func TestFilterDeclaresResponseWantFromConfig(t *testing.T) {
	for _, tc := range []struct {
		name           string
		raw            string
		ruleWants      bool
		wantRequestOps int
	}{
		{
			name:           "request only",
			raw:            `{"request":{"set":[{"name":"X-A","value":"1"}]}}`,
			ruleWants:      false,
			wantRequestOps: 1,
		},
		{
			name:           "request plus empty response object",
			raw:            `{"request":{"set":[{"name":"X-A","value":"1"}]},"response":{}}`,
			ruleWants:      false,
			wantRequestOps: 1,
		},
		{
			name:           "response only",
			raw:            `{"response":{"remove":["Server"]}}`,
			ruleWants:      true,
			wantRequestOps: 0,
		},
		{
			name:           "both phases",
			raw:            `{"request":{"set":[{"name":"X-A","value":"1"}]},"response":{"add":[{"name":"X-B","value":"2"}]}}`,
			ruleWants:      true,
			wantRequestOps: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parse(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
				inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil,
			)})
			// Subscription is declared from the config, not returned from the
			// action: Envoy accepts a mode_override only on a header-phase reply,
			// and this filter is ordered after one that pauses for the request
			// body, so an action-borne subscription would arrive too late.
			wantPhase := filter.Phase(0)
			if tc.ruleWants {
				wantPhase = filter.PhaseResponseHeaders
			}
			if got := Descriptor().SubscribesOf(cfg); got != wantPhase {
				t.Errorf("SubscribesOf = %v, want %v", got, wantPhase)
			}

			got, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
			if err != nil {
				t.Fatalf("OnRequestHeaders: %v", err)
			}
			if len(got.Mutations()) != tc.wantRequestOps {
				t.Errorf("request mutations = %+v, want %d", got.Mutations(), tc.wantRequestOps)
			}
		})
	}
}

func TestFilterResponsePhaseIgnoresRequestOnlyOperations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{"request":{"set":[{"name":"X-A","value":"1"}],"remove":["X-B"]}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
		inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil,
	)})
	got, err := f.OnResponseHeaders(context.Background(), &filter.Stream{})
	if err != nil {
		t.Fatalf("OnResponseHeaders: %v", err)
	}
	if !got.Equal(filter.Continue()) {
		t.Errorf("action = %+v, want a bare Continue", got)
	}
}

func TestFilterRejectsMissingKeySentinel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		invoke func(f filter.Filter) (filter.Action, error)
	}{
		{
			name: "request phase",
			raw:  `{"request":{"set":[{"name":"X-A","value":"{{ index .Inputs \"absent\" }}"}]}}`,
			invoke: func(f filter.Filter) (filter.Action, error) {
				return f.OnRequestHeaders(context.Background(), &filter.Stream{})
			},
		},
		{
			name: "response phase",
			raw:  `{"response":{"add":[{"name":"X-A","value":"{{ index .Inputs \"absent\" }}"}]}}`,
			invoke: func(f filter.Filter) (filter.Action, error) {
				return f.OnResponseHeaders(context.Background(), &filter.Stream{})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parse(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
				inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{},
				map[string]any{"present": "yes"},
			)})
			got, err := tc.invoke(f)
			if err == nil {
				t.Fatalf("render succeeded with action %+v, want a <no value> error", got)
			}
			if len(got.Mutations()) != 0 {
				t.Errorf("error action carries mutations %+v, want none", got.Mutations())
			}
		})
	}
}

func TestFilterRejectsInvalidRenderedResponseValueWithoutPartialMutation(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"response": {
			"set": [
				{"name": "X-Valid", "value": "rendered-first"},
				{"name": "X-Invalid", "value": "bad\r\nx-injected: value"}
			],
			"remove": ["Server"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
		inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil,
	)})

	got, err := f.OnResponseHeaders(context.Background(), &filter.Stream{})
	if err == nil {
		t.Fatal("OnResponseHeaders succeeded, want invalid header value error")
	}
	if len(got.Mutations()) != 0 {
		t.Fatalf("error action carries mutations %+v, want none", got.Mutations())
	}
}

func TestDescriptorDeclaresBothHeaderPhases(t *testing.T) {
	phases := Descriptor().Phases
	if phases&filter.PhaseRequestHeaders == 0 {
		t.Error("Phases missing PhaseRequestHeaders")
	}
	if phases&filter.PhaseResponseHeaders == 0 {
		t.Error("Phases missing PhaseResponseHeaders")
	}
}

func TestFilterRejectsInvalidRenderedValueWithoutPartialMutation(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"request": {
			"set": [
				{"name": "X-Valid", "value": "rendered-first"},
				{"name": "X-Invalid", "value": "bad\r\nx-injected: value"}
			]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f := New(filter.RuleConfig[Config]{Cfg: cfg, Scope: inputs.NewScope(
		inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil,
	)})

	got, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
	if err == nil {
		t.Fatal("OnRequestHeaders succeeded, want invalid header value error")
	}
	if len(got.Mutations()) != 0 {
		t.Fatalf("error action carries mutations %+v, want none", got.Mutations())
	}
}
