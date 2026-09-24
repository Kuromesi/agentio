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
	"reflect"
	"strings"
	"testing"
)

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := parse([]byte(`{"provider":"scanner","request":{}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Config{
		Provider:     "scanner",
		Request:      &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeNone}},
		MaxBodyBytes: DefaultMaxBodyBytes,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parse = %#v, want %#v", cfg, want)
	}
}

// TestParsePhasePresenceIsEnablement pins the wire rule that makes a header mode
// on a disabled phase unrepresentable: an absent key disables the direction, and
// an empty object enables it with nothing disclosed and nothing buffered.
func TestParsePhasePresenceIsEnablement(t *testing.T) {
	t.Run("an absent key disables the phase", func(t *testing.T) {
		cfg, err := parse([]byte(`{"provider":"scanner","request":{}}`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.Response != nil {
			t.Errorf("Response = %#v, want nil for an absent key", cfg.Response)
		}
	})

	t.Run("an empty object is the cheapest useful callout", func(t *testing.T) {
		cfg, err := parse([]byte(`{"provider":"scanner","response":{}}`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.Response == nil {
			t.Fatal("Response = nil, want an enabled phase for a present empty object")
		}
		if cfg.Response.Headers.Mode != HeaderModeNone || cfg.Response.Body {
			t.Errorf("Response = %#v, want no disclosure and no body", *cfg.Response)
		}
	})
}

func TestParseReadsEveryField(t *testing.T) {
	cfg, err := parse([]byte(`{
		"provider":"scanner",
		"request":{"headers":{"mode":"allowlist","allowlist":["X-Tenant","x-tenant","X-Trace"]},"body":true},
		"response":{"headers":{"mode":"allowlist","allowlist":["X-Upstream","x-upstream","X-Trace"]}},
				"maxBodyBytes":4096,
		"failOpen":true
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Config{
		Provider:     "scanner",
		MaxBodyBytes: 4096,
		FailOpen:     true,
		Request: &PhaseConfig{
			Headers: HeadersConfig{
				Mode: HeaderModeAllowlist,
				// Effective lower-cases and de-duplicates.
				Allowlist: []string{"x-tenant", "x-trace"},
			},
			Body: true,
		},
		Response: &PhaseConfig{
			Headers: HeadersConfig{
				Mode:      HeaderModeAllowlist,
				Allowlist: []string{"x-upstream", "x-trace"},
			},
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parse = %#v, want %#v", cfg, want)
	}
}

// TestParseReadsADenylist pins the wire contract for the mode that replaces the
// old hardcoded credential rule: the recommended baseline for an endpoint outside
// the trust boundary has to be writable in the payload an operator reviews.
func TestParseReadsADenylist(t *testing.T) {
	cfg, err := parse([]byte(`{
		"provider":"scanner",
		"request":{"headers":{"mode":"denylist","denylist":["Authorization","authorization","Proxy-Authorization","Cookie"]}},
		"response":{"headers":{"mode":"denylist","denylist":["Set-Cookie"]}}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Config{
		Provider:     "scanner",
		MaxBodyBytes: DefaultMaxBodyBytes,
		Request: &PhaseConfig{
			Headers: HeadersConfig{
				Mode:     HeaderModeDenylist,
				Denylist: []string{"authorization", "proxy-authorization", "cookie"},
			},
		},
		Response: &PhaseConfig{
			Headers: HeadersConfig{
				Mode:     HeaderModeDenylist,
				Denylist: []string{"set-cookie"},
			},
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parse = %#v, want %#v", cfg, want)
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name:    "not an object",
			raw:     `[]`,
			wantErr: "cannot unmarshal",
		},
		{
			name:    "unknown field",
			raw:     `{"provider":"scanner","request":{},"retries":3}`,
			wantErr: "retries",
		},
		{
			// An empty document is "mine but says nothing", which is a policy
			// authoring mistake rather than a config with all defaults.
			name:    "empty object",
			raw:     `{}`,
			wantErr: "empty",
		},
		{
			name:    "no phase enabled",
			raw:     `{"provider":"scanner"}`,
			wantErr: "phase",
		},
		{
			name:    "missing provider",
			raw:     `{"request":{}}`,
			wantErr: "provider",
		},
		{
			name:    "endpoint belongs to provider",
			raw:     `{"endpoint":"/inspect","request":{}}`,
			wantErr: "endpoint",
		},
		{
			name:    "malformed timeout",
			raw:     `{"provider":"scanner","request":{},"timeout":"soon"}`,
			wantErr: "timeout",
		},
		{
			name:    "negative timeout",
			raw:     `{"provider":"scanner","request":{},"timeout":"-1s"}`,
			wantErr: "timeout",
		},
		{
			name:    "negative body limit",
			raw:     `{"provider":"scanner","request":{},"maxBodyBytes":-1}`,
			wantErr: "negative",
		},
		{
			name:    "unknown header mode",
			raw:     `{"provider":"scanner","request":{"headers":{"mode":"some"}}}`,
			wantErr: "mode",
		},
		{
			name:    "allowlist without allowlist mode",
			raw:     `{"provider":"scanner","request":{"headers":{"mode":"all","allowlist":["x-a"]}}}`,
			wantErr: "allowlist",
		},
		{
			name:    "denylist without denylist mode",
			raw:     `{"provider":"scanner","request":{"headers":{"mode":"allowlist","allowlist":["x-a"],"denylist":["x-b"]}}}`,
			wantErr: "denylist",
		},
		{
			name:    "unknown response header mode",
			raw:     `{"provider":"scanner","response":{"headers":{"mode":"some"}}}`,
			wantErr: "mode",
		},
		{
			name:    "unknown field inside a phase's headers",
			raw:     `{"provider":"scanner","response":{"headers":{"mode":"all","blocklist":["x-a"]}}}`,
			wantErr: "blocklist",
		},
		{
			// The nested objects must reject typos as firmly as the top level, or
			// "bodies":true would silently leave body collection off.
			name:    "unknown field inside a phase",
			raw:     `{"provider":"scanner","request":{"bodies":true}}`,
			wantErr: "bodies",
		},
		{
			// The flat shape is what this change replaced; accepting it would let a
			// stale payload enable a phase the new parser never sees.
			name:    "the old flat boolean phase",
			raw:     `{"provider":"scanner","request":true}`,
			wantErr: "cannot unmarshal",
		},
		{
			name:    "the old flat header field",
			raw:     `{"provider":"scanner","request":{},"requestHeaders":{"mode":"all"}}`,
			wantErr: "requestheaders",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parse([]byte(tc.raw))
			if err == nil {
				t.Fatalf("parse succeeded with %#v, want an error", cfg)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
