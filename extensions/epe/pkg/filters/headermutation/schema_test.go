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
	"encoding/json"
	"testing"

	"istio.io/istio/extensions/epe/pkg/eval"
)

func TestParseCompilesAndNormalizesOperations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"set": [
			{"name": "X-Tenant-ID", "value": "tenant"},
			{"name": "X-Client", "value": "client"}
		],
		"add": [{"name": "X-Tag", "value": "tag"}],
		"remove": ["X-Legacy"]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(cfg.Set) != 2 || cfg.Set[0].Name != "x-tenant-id" || cfg.Set[1].Name != "x-client" {
		t.Fatalf("Set = %+v, want ordered lowercase names", cfg.Set)
	}
	if len(cfg.Add) != 1 || cfg.Add[0].Name != "x-tag" {
		t.Fatalf("Add = %+v, want x-tag", cfg.Add)
	}
	if len(cfg.Remove) != 1 || cfg.Remove[0] != "x-legacy" {
		t.Fatalf("Remove = %+v, want x-legacy", cfg.Remove)
	}

	for _, tc := range []struct {
		name string
		op   ValueOp
		want string
	}{
		{name: "first set", op: cfg.Set[0], want: "tenant"},
		{name: "second set", op: cfg.Set[1], want: "client"},
		{name: "add", op: cfg.Add[0], want: "tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eval.RenderToString(tc.op.Value, nil)
			if err != nil {
				t.Fatalf("render compiled template: %v", err)
			}
			if got != tc.want {
				t.Errorf("rendered value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedMutationSets(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "malformed JSON", raw: `{`},
		{name: "empty mutation set", raw: `{}`},
		{name: "empty header name", raw: `{"set":[{"name":"","value":"v"}]}`},
		{name: "invalid header name", raw: `{"set":[{"name":"bad header","value":"v"}]}`},
		{name: "host header", raw: `{"set":[{"name":"Host","value":"example.com"}]}`},
		{name: "pseudo header", raw: `{"remove":[":path"]}`},
		{name: "duplicate within set", raw: `{"set":[{"name":"X-A","value":"1"},{"name":"x-a","value":"2"}]}`},
		{name: "duplicate across kinds", raw: `{"set":[{"name":"X-A","value":"1"}],"remove":["x-A"]}`},
		{name: "malformed template", raw: `{"add":[{"name":"X-A","value":"{{ .Pod"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err == nil {
				t.Fatal("parse succeeded, want an error")
			}
		})
	}
}
