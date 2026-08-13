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
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/eval"
)

func TestParseCompilesAndNormalizesOperations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"request": {
			"set": [
				{"name": "X-Tenant-ID", "value": "tenant"},
				{"name": "X-Client", "value": "client"}
			],
			"add": [{"name": "X-Tag", "value": "tag"}],
			"remove": ["X-Legacy"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(cfg.Request.Set) != 2 || cfg.Request.Set[0].Name != "x-tenant-id" || cfg.Request.Set[1].Name != "x-client" {
		t.Fatalf("Set = %+v, want ordered lowercase names", cfg.Request.Set)
	}
	if len(cfg.Request.Add) != 1 || cfg.Request.Add[0].Name != "x-tag" {
		t.Fatalf("Add = %+v, want x-tag", cfg.Request.Add)
	}
	if len(cfg.Request.Remove) != 1 || cfg.Request.Remove[0] != "x-legacy" {
		t.Fatalf("Remove = %+v, want x-legacy", cfg.Request.Remove)
	}

	for _, tc := range []struct {
		name string
		op   ValueOp
		want string
	}{
		{name: "first set", op: cfg.Request.Set[0], want: "tenant"},
		{name: "second set", op: cfg.Request.Set[1], want: "client"},
		{name: "add", op: cfg.Request.Add[0], want: "tag"},
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

func TestParseCompilesResponseOperations(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"response": {
			"set": [{"name": "X-Policy", "value": "policy"}],
			"add": [{"name": "X-Epe", "value": "epe"}],
			"remove": ["Server"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Request.Set)+len(cfg.Request.Add)+len(cfg.Request.Remove) != 0 {
		t.Fatalf("request side = %+v, want empty", cfg)
	}
	if !cfg.HasResponseOps() {
		t.Fatal("HasResponseOps() = false, want true")
	}
	if len(cfg.Response.Set) != 1 || cfg.Response.Set[0].Name != "x-policy" {
		t.Fatalf("Response.Set = %+v, want x-policy", cfg.Response.Set)
	}
	if len(cfg.Response.Add) != 1 || cfg.Response.Add[0].Name != "x-epe" {
		t.Fatalf("Response.Add = %+v, want x-epe", cfg.Response.Add)
	}
	if len(cfg.Response.Remove) != 1 || cfg.Response.Remove[0] != "server" {
		t.Fatalf("Response.Remove = %+v, want server", cfg.Response.Remove)
	}
	for _, tc := range []struct {
		name string
		op   ValueOp
		want string
	}{
		{name: "response set", op: cfg.Response.Set[0], want: "policy"},
		{name: "response add", op: cfg.Response.Add[0], want: "epe"},
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

func TestParseResponseOpsPredicate(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "request only",
			raw:  `{"request":{"set":[{"name":"X-A","value":"1"}]}}`,
			want: false,
		},
		{
			name: "request plus empty response object",
			raw:  `{"request":{"set":[{"name":"X-A","value":"1"}]},"response":{}}`,
			want: false,
		},
		{
			name: "response remove only",
			raw:  `{"response":{"remove":["Server"]}}`,
			want: true,
		},
		{
			name: "both phases",
			raw:  `{"request":{"set":[{"name":"X-A","value":"1"}]},"response":{"add":[{"name":"X-B","value":"2"}]}}`,
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parse(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := cfg.HasResponseOps(); got != tc.want {
				t.Errorf("HasResponseOps() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseAcceptsSameNameAcrossPhases(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{
		"request": {
			"set": [{"name": "X-Shared", "value": "req"}],
			"remove": ["X-Gone"]
		},
		"response": {
			"set": [{"name": "x-shared", "value": "resp"}],
			"remove": ["x-gone"]
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Request.Set) != 1 || len(cfg.Response.Set) != 1 {
		t.Fatalf("cfg = %+v, want one set op per phase", cfg)
	}
	if len(cfg.Request.Remove) != 1 || len(cfg.Response.Remove) != 1 {
		t.Fatalf("cfg = %+v, want one remove op per phase", cfg)
	}
}

func TestParseResponseErrorsArePhaseQualified(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "response duplicate across kinds",
			raw:  `{"response":{"set":[{"name":"X-A","value":"1"}],"remove":["x-a"]}}`,
			want: "response.",
		},
		{
			name: "response invalid name",
			raw:  `{"response":{"set":[{"name":"bad header","value":"v"}]}}`,
			want: "response.set",
		},
		{
			name: "response malformed template",
			raw:  `{"response":{"add":[{"name":"X-A","value":"{{ .Pod"}]}}`,
			want: "response.add",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(json.RawMessage(tc.raw))
			if err == nil {
				t.Fatal("parse succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseRejectsForbiddenNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "request x-envoy set", raw: `{"request":{"set":[{"name":"X-Envoy-Foo","value":"v"}]}}`},
		{name: "request x-envoy remove", raw: `{"request":{"remove":["x-envoy-decorator-operation"]}}`},
		{name: "request exact x-envoy", raw: `{"request":{"remove":["X-Envoy"]}}`},
		// Envoy's own gate is a bare StartsWith on the "x-envoy" prefix
		// (mutation_rules.cc:97), so a name that merely begins with it — no
		// hyphen — is also silently ignored by the data plane and must be
		// rejected here rather than accepted and lost at runtime.
		{name: "request x-envoy bare prefix no hyphen", raw: `{"request":{"remove":["x-envoyer"]}}`},
		{name: "response x-envoy bare prefix no hyphen", raw: `{"response":{"add":[{"name":"X-Envoyer","value":"v"}]}}`},
		{name: "response host set", raw: `{"response":{"set":[{"name":"Host","value":"example.com"}]}}`},
		{name: "response host remove", raw: `{"response":{"remove":["host"]}}`},
		{name: "response x-envoy add", raw: `{"response":{"add":[{"name":"x-envoy-bar","value":"v"}]}}`},
		{name: "response content-length set", raw: `{"response":{"set":[{"name":"Content-Length","value":"5"}]}}`},
		{name: "response content-length add", raw: `{"response":{"add":[{"name":"content-length","value":"5"}]}}`},
		{name: "response transfer-encoding set", raw: `{"response":{"set":[{"name":"Transfer-Encoding","value":"chunked"}]}}`},
		{name: "response transfer-encoding add", raw: `{"response":{"add":[{"name":"transfer-encoding","value":"chunked"}]}}`},
		{name: "response connection", raw: `{"response":{"set":[{"name":"Connection","value":"close"}]}}`},
		{name: "response keep-alive", raw: `{"response":{"remove":["Keep-Alive"]}}`},
		{name: "response proxy-connection", raw: `{"response":{"remove":["proxy-connection"]}}`},
		{name: "response upgrade", raw: `{"response":{"remove":["Upgrade"]}}`},
		{name: "response te", raw: `{"response":{"remove":["TE"]}}`},
		{name: "response trailer", raw: `{"response":{"remove":["Trailer"]}}`},
		{name: "response proxy-authenticate", raw: `{"response":{"remove":["Proxy-Authenticate"]}}`},
		{name: "response content-encoding", raw: `{"response":{"remove":["Content-Encoding"]}}`},
		{name: "response pseudo header", raw: `{"response":{"set":[{"name":":status","value":"418"}]}}`},
		{name: "response pseudo header remove", raw: `{"response":{"remove":[":status"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err == nil {
				t.Fatal("parse succeeded, want an error")
			}
		})
	}
}

func TestParseAllowsResponseNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "set-cookie set", raw: `{"response":{"set":[{"name":"Set-Cookie","value":"a=b"}]}}`},
		{name: "set-cookie add", raw: `{"response":{"add":[{"name":"set-cookie","value":"a=b"}]}}`},
		{name: "content-type", raw: `{"response":{"set":[{"name":"Content-Type","value":"application/json"}]}}`},
		{name: "location", raw: `{"response":{"set":[{"name":"Location","value":"https://example.com"}]}}`},
		{name: "content-length remove", raw: `{"response":{"remove":["Content-Length"]}}`},
		{name: "transfer-encoding remove", raw: `{"response":{"remove":["Transfer-Encoding"]}}`},
		{name: "server remove", raw: `{"response":{"remove":["Server"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
	}
}

func TestParseProbeRendersTemplates(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "request unknown struct field", raw: `{"request":{"set":[{"name":"X-A","value":"{{ .Response.Status }}"}]}}`},
		{name: "response unknown struct field", raw: `{"response":{"set":[{"name":"X-A","value":"{{ .Response.Status }}"}]}}`},
		{name: "response unknown method", raw: `{"response":{"add":[{"name":"X-A","value":"{{ .Nope }}"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err == nil {
				t.Fatal("parse succeeded, want a probe-render error")
			}
		})
	}
}

func TestParseProbeAcceptsDataDependentTemplates(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "unknown input key", raw: `{"request":{"set":[{"name":"X-A","value":"{{ index .Inputs \"tag\" }}"}]}}`},
		{name: "pod label", raw: `{"response":{"set":[{"name":"X-A","value":"{{ .Pod.Label \"app\" }}"}]}}`},
		{name: "request header", raw: `{"response":{"add":[{"name":"X-A","value":"{{ .Request.Header \"x-id\" }}"}]}}`},
		{name: "rule name", raw: `{"response":{"add":[{"name":"X-B","value":"{{ .Rule.Name }}"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err != nil {
				t.Fatalf("parse: %v", err)
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
		{name: "empty response object only", raw: `{"response":{}}`},
		{name: "both phases empty", raw: `{"request":{"set":[]},"response":{"set":[],"add":[],"remove":[]}}`},
		{name: "empty header name", raw: `{"request":{"set":[{"name":"","value":"v"}]}}`},
		{name: "invalid header name", raw: `{"request":{"set":[{"name":"bad header","value":"v"}]}}`},
		{name: "host header", raw: `{"request":{"set":[{"name":"Host","value":"example.com"}]}}`},
		{name: "pseudo header", raw: `{"request":{"remove":[":path"]}}`},
		{name: "duplicate within set", raw: `{"request":{"set":[{"name":"X-A","value":"1"},{"name":"x-a","value":"2"}]}}`},
		{name: "duplicate across kinds", raw: `{"request":{"set":[{"name":"X-A","value":"1"}],"remove":["x-A"]}}`},
		{name: "malformed template", raw: `{"request":{"add":[{"name":"X-A","value":"{{ .Pod"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(json.RawMessage(tc.raw)); err == nil {
				t.Fatal("parse succeeded, want an error")
			}
		})
	}
}
