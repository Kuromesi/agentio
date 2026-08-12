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
		"set": [
			{"name": "X-Tenant", "value": "{{ .Pod.Namespace }}:{{ .Request.Header \"X-Source\" }}"},
			{"name": "X-Policy", "value": "{{ .Profile.Name }}/{{ .Rule.Name }}"}
		],
		"add": [{"name": "X-Tag", "value": "{{ index .Inputs \"tag\" }}"}],
		"remove": ["X-Legacy"]
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

func TestFilterRejectsInvalidRenderedValueWithoutPartialMutation(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"set": [
			{"name": "X-Valid", "value": "rendered-first"},
			{"name": "X-Invalid", "value": "bad\r\nx-injected: value"}
		]
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
