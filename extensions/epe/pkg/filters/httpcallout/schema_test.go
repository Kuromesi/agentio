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
	"time"
)

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := parse([]byte(`{"endpoint":"https://scanner.example.com/inspect","request":true}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Config{
		Endpoint:        "https://scanner.example.com/inspect",
		Request:         true,
		Timeout:         DefaultTimeout,
		MaxBodyBytes:    DefaultMaxBodyBytes,
		RequestHeaders:  HeadersConfig{Mode: HeaderModeNone},
		ResponseHeaders: HeadersConfig{Mode: HeaderModeNone},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parse = %#v, want %#v", cfg, want)
	}
}

func TestParseReadsEveryField(t *testing.T) {
	cfg, err := parse([]byte(`{
		"endpoint":"https://scanner.example.com/inspect",
		"request":true,
		"response":true,
		"timeout":"2s",
		"maxBodyBytes":4096,
		"failOpen":true,
		"requestHeaders":{"mode":"allowlist","allowlist":["X-Tenant","x-tenant","X-Trace"]},
		"responseHeaders":{"mode":"allowlist","allowlist":["X-Upstream","x-upstream","X-Trace"]}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Config{
		Endpoint:     "https://scanner.example.com/inspect",
		Request:      true,
		Response:     true,
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
		FailOpen:     true,
		RequestHeaders: HeadersConfig{
			Mode: HeaderModeAllowlist,
			// Effective lower-cases and de-duplicates.
			Allowlist: []string{"x-tenant", "x-trace"},
		},
		ResponseHeaders: HeadersConfig{
			Mode:      HeaderModeAllowlist,
			Allowlist: []string{"x-upstream", "x-trace"},
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parse = %#v, want %#v", cfg, want)
	}
}

// TestParseTimeoutIsADurationString pins the wire representation. A bare JSON
// number would be ambiguous between seconds, milliseconds, and nanoseconds, and
// the zero-means-default rule makes a wrong guess silent.
func TestParseTimeoutIsADurationString(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{raw: `"250ms"`, want: 250 * time.Millisecond},
		{raw: `"1.5s"`, want: 1500 * time.Millisecond},
		{raw: `"1m"`, want: time.Minute},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg, err := parse([]byte(`{"endpoint":"https://x.example.com","request":true,"timeout":` + tc.raw + `}`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Timeout != tc.want {
				t.Fatalf("timeout = %v, want %v", cfg.Timeout, tc.want)
			}
		})
	}

	t.Run("empty string means the default", func(t *testing.T) {
		cfg, err := parse([]byte(`{"endpoint":"https://x.example.com","request":true,"timeout":""}`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.Timeout != DefaultTimeout {
			t.Fatalf("timeout = %v, want the default %v", cfg.Timeout, DefaultTimeout)
		}
	})

	t.Run("a bare number is rejected rather than guessed", func(t *testing.T) {
		if _, err := parse([]byte(`{"endpoint":"https://x.example.com","request":true,"timeout":500}`)); err == nil {
			t.Fatal("parse accepted a unitless timeout, want an error naming the unit requirement")
		}
	})
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
			raw:     `{"endpoint":"https://x.example.com","request":true,"retries":3}`,
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
			raw:     `{"endpoint":"https://x.example.com"}`,
			wantErr: "phase",
		},
		{
			name:    "missing endpoint",
			raw:     `{"request":true}`,
			wantErr: "endpoint",
		},
		{
			name:    "relative endpoint",
			raw:     `{"endpoint":"/inspect","request":true}`,
			wantErr: "absolute",
		},
		{
			name:    "malformed timeout",
			raw:     `{"endpoint":"https://x.example.com","request":true,"timeout":"soon"}`,
			wantErr: "timeout",
		},
		{
			name:    "negative timeout",
			raw:     `{"endpoint":"https://x.example.com","request":true,"timeout":"-1s"}`,
			wantErr: "negative",
		},
		{
			name:    "negative body limit",
			raw:     `{"endpoint":"https://x.example.com","request":true,"maxBodyBytes":-1}`,
			wantErr: "negative",
		},
		{
			name:    "allowlist naming a credential header",
			raw:     `{"endpoint":"https://x.example.com","request":true,"requestHeaders":{"mode":"allowlist","allowlist":["Authorization"]}}`,
			wantErr: "never forwarded",
		},
		{
			name:    "unknown header mode",
			raw:     `{"endpoint":"https://x.example.com","request":true,"requestHeaders":{"mode":"some"}}`,
			wantErr: "mode",
		},
		{
			name:    "allowlist without allowlist mode",
			raw:     `{"endpoint":"https://x.example.com","request":true,"requestHeaders":{"mode":"all","allowlist":["x-a"]}}`,
			wantErr: "allowlist",
		},
		{
			name:    "response allowlist naming an upstream credential",
			raw:     `{"endpoint":"https://x.example.com","response":true,"responseHeaders":{"mode":"allowlist","allowlist":["Set-Cookie"]}}`,
			wantErr: "never forwarded",
		},
		{
			name:    "unknown response header mode",
			raw:     `{"endpoint":"https://x.example.com","response":true,"responseHeaders":{"mode":"some"}}`,
			wantErr: "mode",
		},
		{
			name:    "unknown field inside responseHeaders",
			raw:     `{"endpoint":"https://x.example.com","response":true,"responseHeaders":{"mode":"all","denylist":["x-a"]}}`,
			wantErr: "denylist",
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
