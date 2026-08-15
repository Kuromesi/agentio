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

func TestConfigEffectiveAppliesDefaultsAndNormalizesAllowlist(t *testing.T) {
	original := Config{
		Endpoint: "https://callout.example.test/v1/check?tenant=a",
		Request:  true,
		Response: true,
		RequestHeaders: HeadersConfig{
			Mode:      HeaderModeAllowlist,
			Allowlist: []string{"X-Tenant", "x-tenant", "X-Trace-ID"},
		},
		ResponseHeaders: HeadersConfig{
			Mode:      HeaderModeAllowlist,
			Allowlist: []string{"X-Upstream", "x-upstream", "X-Trace-ID"},
		},
	}

	got, err := original.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.Timeout != 500*time.Millisecond {
		t.Errorf("Timeout = %v, want 500ms", got.Timeout)
	}
	if got.MaxBodyBytes != 1<<20 {
		t.Errorf("MaxBodyBytes = %d, want %d", got.MaxBodyBytes, 1<<20)
	}
	wantHeaders := HeadersConfig{
		Mode:      HeaderModeAllowlist,
		Allowlist: []string{"x-tenant", "x-trace-id"},
	}
	if !reflect.DeepEqual(got.RequestHeaders, wantHeaders) {
		t.Errorf("RequestHeaders = %#v, want %#v", got.RequestHeaders, wantHeaders)
	}
	wantResponseHeaders := HeadersConfig{
		Mode:      HeaderModeAllowlist,
		Allowlist: []string{"x-upstream", "x-trace-id"},
	}
	if !reflect.DeepEqual(got.ResponseHeaders, wantResponseHeaders) {
		t.Errorf("ResponseHeaders = %#v, want %#v", got.ResponseHeaders, wantResponseHeaders)
	}

	got.RequestHeaders.Allowlist[0] = "changed"
	if original.RequestHeaders.Allowlist[0] != "X-Tenant" {
		t.Fatal("Effective mutated or aliased the caller-owned allowlist")
	}
}

// TestConfigEffectiveDefaultsBothDirectionsToNone pins that disclosure is opt-in
// in both directions: response headers carry upstream-minted credentials such as
// set-cookie, so they are no more forwardable by default than request headers.
func TestConfigEffectiveDefaultsBothDirectionsToNone(t *testing.T) {
	got, err := (Config{
		Endpoint: "http://callout.default.svc/check",
		Request:  true,
		Response: true,
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.RequestHeaders.Mode != HeaderModeNone {
		t.Errorf("request header mode = %q, want %q", got.RequestHeaders.Mode, HeaderModeNone)
	}
	if len(got.RequestHeaders.Allowlist) != 0 {
		t.Errorf("request header allowlist = %v, want empty", got.RequestHeaders.Allowlist)
	}
	if got.ResponseHeaders.Mode != HeaderModeNone {
		t.Errorf("response header mode = %q, want %q", got.ResponseHeaders.Mode, HeaderModeNone)
	}
	if len(got.ResponseHeaders.Allowlist) != 0 {
		t.Errorf("response header allowlist = %v, want empty", got.ResponseHeaders.Allowlist)
	}
}

func TestConfigEffectivePreservesExplicitOverrides(t *testing.T) {
	got, err := (Config{
		Endpoint:     "https://callout.example.test/check",
		Response:     true,
		Timeout:      2 * time.Second,
		MaxBodyBytes: 8 << 20,
		FailOpen:     true,
		RequestHeaders: HeadersConfig{
			Mode: HeaderModeAll,
		},
		ResponseHeaders: HeadersConfig{
			Mode: HeaderModeAll,
		},
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.Timeout != 2*time.Second || got.MaxBodyBytes != 8<<20 || !got.FailOpen {
		t.Errorf("explicit settings were not preserved: %+v", got)
	}
}

func TestConfigEffectiveRejectsInvalidConfiguration(t *testing.T) {
	valid := Config{Endpoint: "https://callout.example.test/check", Request: true}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "no phase",
			mutate:  func(c *Config) { c.Request = false },
			wantErr: "phase",
		},
		{
			name:    "empty endpoint",
			mutate:  func(c *Config) { c.Endpoint = "" },
			wantErr: "endpoint",
		},
		{
			name:    "relative endpoint",
			mutate:  func(c *Config) { c.Endpoint = "/check" },
			wantErr: "absolute",
		},
		{
			name:    "unsupported endpoint scheme",
			mutate:  func(c *Config) { c.Endpoint = "grpc://callout.example.test/check" },
			wantErr: "scheme",
		},
		{
			name:    "endpoint user info",
			mutate:  func(c *Config) { c.Endpoint = "https://user:pass@callout.example.test/check" },
			wantErr: "user info",
		},
		{
			name:    "endpoint fragment",
			mutate:  func(c *Config) { c.Endpoint += "#fragment" },
			wantErr: "fragment",
		},
		{
			name:    "negative timeout",
			mutate:  func(c *Config) { c.Timeout = -time.Millisecond },
			wantErr: "timeout",
		},
		{
			name:    "negative body limit",
			mutate:  func(c *Config) { c.MaxBodyBytes = -1 },
			wantErr: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if _, err := cfg.Effective(); err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("Effective error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestConfigEffectiveRejectsInvalidHeaderConfigInBothDirections runs one table
// against both directions: the modes are identical in semantics, so a rule that
// holds for the request side and not the response side would be a bug rather
// than a design.
func TestConfigEffectiveRejectsInvalidHeaderConfigInBothDirections(t *testing.T) {
	directions := []struct {
		name       string
		field      func(*Config) *HeadersConfig
		credential string
	}{
		{
			name:       "request",
			field:      func(c *Config) *HeadersConfig { return &c.RequestHeaders },
			credential: "authorization",
		},
		{
			name:       "response",
			field:      func(c *Config) *HeadersConfig { return &c.ResponseHeaders },
			credential: "set-cookie",
		},
	}
	tests := []struct {
		name    string
		mutate  func(*HeadersConfig, string)
		wantErr string
	}{
		{
			name:    "unknown mode",
			mutate:  func(h *HeadersConfig, _ string) { h.Mode = HeaderMode("unknown") },
			wantErr: "header mode",
		},
		{
			name:    "empty allowlist",
			mutate:  func(h *HeadersConfig, _ string) { h.Mode = HeaderModeAllowlist },
			wantErr: "allowlist",
		},
		{
			name: "invalid allowlist name",
			mutate: func(h *HeadersConfig, _ string) {
				h.Mode = HeaderModeAllowlist
				h.Allowlist = []string{"bad header"}
			},
			wantErr: "header name",
		},
		{
			name: "allowlist entries in none mode",
			mutate: func(h *HeadersConfig, _ string) {
				h.Mode = HeaderModeNone
				h.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "allowlist entries in all mode",
			mutate: func(h *HeadersConfig, _ string) {
				h.Mode = HeaderModeAll
				h.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "allowlist naming a credential",
			mutate: func(h *HeadersConfig, credential string) {
				h.Mode = HeaderModeAllowlist
				h.Allowlist = []string{"x-tenant", credential}
			},
			wantErr: "never forwarded",
		},
		{
			name: "allowlist naming a mixed-case credential",
			mutate: func(h *HeadersConfig, credential string) {
				h.Mode = HeaderModeAllowlist
				h.Allowlist = []string{strings.ToUpper(credential)}
			},
			wantErr: "never forwarded",
		},
	}

	for _, direction := range directions {
		t.Run(direction.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					cfg := Config{Endpoint: "https://callout.example.test/check", Request: true, Response: true}
					tt.mutate(direction.field(&cfg), direction.credential)
					_, err := cfg.Effective()
					if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
						t.Fatalf("Effective error = %v, want one containing %q", err, tt.wantErr)
					}
					// The message must name the direction, or an operator with
					// both fields set cannot tell which one is wrong.
					if !strings.Contains(strings.ToLower(err.Error()), direction.name) {
						t.Errorf("error = %q, want it to name the %s direction", err.Error(), direction.name)
					}
				})
			}
		})
	}
}

// TestConfigEffectiveKeepsTheNeverForwardSetsPerDirection is the leak bite. The
// two sets protect different secrets: cookie is a credential the caller sent,
// set-cookie one the upstream minted. Sharing one set would forbid names that are
// harmless in the other direction.
func TestConfigEffectiveKeepsTheNeverForwardSetsPerDirection(t *testing.T) {
	requestNames := []string{"authorization", "proxy-authorization", "cookie"}
	responseNames := []string{"set-cookie", "www-authenticate", "proxy-authenticate"}

	t.Run("a request allowlist may name response credentials", func(t *testing.T) {
		got, err := (Config{
			Endpoint:       "https://callout.example.test/check",
			Request:        true,
			RequestHeaders: HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: responseNames},
		}).Effective()
		if err != nil {
			t.Fatalf("Effective rejected %v in a request allowlist: %v", responseNames, err)
		}
		if !reflect.DeepEqual(got.RequestHeaders.Allowlist, responseNames) {
			t.Errorf("request allowlist = %v, want %v", got.RequestHeaders.Allowlist, responseNames)
		}
	})

	t.Run("a response allowlist may name request credentials", func(t *testing.T) {
		got, err := (Config{
			Endpoint:        "https://callout.example.test/check",
			Response:        true,
			ResponseHeaders: HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: requestNames},
		}).Effective()
		if err != nil {
			t.Fatalf("Effective rejected %v in a response allowlist: %v", requestNames, err)
		}
		if !reflect.DeepEqual(got.ResponseHeaders.Allowlist, requestNames) {
			t.Errorf("response allowlist = %v, want %v", got.ResponseHeaders.Allowlist, requestNames)
		}
	})
}

func TestNeverForwardHeader(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          string
		wantRequest bool
		wantRespond bool
	}{
		{name: "authorization", in: "authorization", wantRequest: true},
		{name: "mixed-case authorization", in: "Authorization", wantRequest: true},
		{name: "proxy-authorization", in: "proxy-authorization", wantRequest: true},
		{name: "mixed-case proxy-authorization", in: "Proxy-Authorization", wantRequest: true},
		{name: "cookie", in: "cookie", wantRequest: true},
		{name: "mixed-case cookie", in: "Cookie", wantRequest: true},
		{name: "set-cookie", in: "set-cookie", wantRespond: true},
		{name: "mixed-case set-cookie", in: "Set-Cookie", wantRespond: true},
		{name: "www-authenticate", in: "www-authenticate", wantRespond: true},
		{name: "mixed-case www-authenticate", in: "WWW-Authenticate", wantRespond: true},
		{name: "proxy-authenticate", in: "proxy-authenticate", wantRespond: true},
		{name: "ordinary header", in: "x-tenant"},
		{name: "content-type", in: "Content-Type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := neverForwardRequestHeader(tc.in); got != tc.wantRequest {
				t.Errorf("neverForwardRequestHeader(%q) = %v, want %v", tc.in, got, tc.wantRequest)
			}
			if got := neverForwardResponseHeader(tc.in); got != tc.wantRespond {
				t.Errorf("neverForwardResponseHeader(%q) = %v, want %v", tc.in, got, tc.wantRespond)
			}
		})
	}
}
