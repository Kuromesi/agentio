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
		RequestHeaders: RequestHeadersConfig{
			Mode:      RequestHeadersAllowlist,
			Allowlist: []string{"X-Tenant", "x-tenant", "X-Trace-ID"},
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
	wantHeaders := RequestHeadersConfig{
		Mode:      RequestHeadersAllowlist,
		Allowlist: []string{"x-tenant", "x-trace-id"},
	}
	if !reflect.DeepEqual(got.RequestHeaders, wantHeaders) {
		t.Errorf("RequestHeaders = %#v, want %#v", got.RequestHeaders, wantHeaders)
	}

	got.RequestHeaders.Allowlist[0] = "changed"
	if original.RequestHeaders.Allowlist[0] != "X-Tenant" {
		t.Fatal("Effective mutated or aliased the caller-owned allowlist")
	}
}

func TestConfigEffectiveDefaultsRequestHeadersToNone(t *testing.T) {
	got, err := (Config{
		Endpoint: "http://callout.default.svc/check",
		Request:  true,
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.RequestHeaders.Mode != RequestHeadersNone {
		t.Errorf("request header mode = %q, want %q", got.RequestHeaders.Mode, RequestHeadersNone)
	}
	if len(got.RequestHeaders.Allowlist) != 0 {
		t.Errorf("request header allowlist = %v, want empty", got.RequestHeaders.Allowlist)
	}
}

func TestConfigEffectivePreservesExplicitOverrides(t *testing.T) {
	got, err := (Config{
		Endpoint:     "https://callout.example.test/check",
		Response:     true,
		Timeout:      2 * time.Second,
		MaxBodyBytes: 8 << 20,
		FailOpen:     true,
		RequestHeaders: RequestHeadersConfig{
			Mode: RequestHeadersAll,
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
		{
			name: "unknown request header mode",
			mutate: func(c *Config) {
				c.RequestHeaders.Mode = RequestHeaderMode("unknown")
			},
			wantErr: "header mode",
		},
		{
			name: "empty allowlist",
			mutate: func(c *Config) {
				c.RequestHeaders.Mode = RequestHeadersAllowlist
			},
			wantErr: "allowlist",
		},
		{
			name: "invalid allowlist name",
			mutate: func(c *Config) {
				c.RequestHeaders.Mode = RequestHeadersAllowlist
				c.RequestHeaders.Allowlist = []string{"bad header"}
			},
			wantErr: "header name",
		},
		{
			name: "allowlist entries in none mode",
			mutate: func(c *Config) {
				c.RequestHeaders.Mode = RequestHeadersNone
				c.RequestHeaders.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "allowlist entries in all mode",
			mutate: func(c *Config) {
				c.RequestHeaders.Mode = RequestHeadersAll
				c.RequestHeaders.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
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
