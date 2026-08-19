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
package attributes

import (
	"context"
	"testing"
)

func TestParseHTTPRequest(t *testing.T) {
	h1 := map[string]string{":authority": "api.openai.com", ":path": "/v1/chat", ":method": "POST"}
	info1 := parseHTTPRequest(context.Background(), h1)
	if info1.Host != "api.openai.com" {
		t.Errorf("expected host 'api.openai.com', got %q", info1.Host)
	}
	if info1.Path != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", info1.Path)
	}
	if info1.Method != "POST" {
		t.Errorf("expected method 'POST', got %q", info1.Method)
	}

	h2 := map[string]string{"host": "example.com", ":path": "/api"}
	info2 := parseHTTPRequest(context.Background(), h2)
	if info2.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", info2.Host)
	}
}

// TestSplitHostPort exercises the (host, port) extractor, including IPv6.
func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int32
	}{
		{"", "", 0},
		{"example.com", "example.com", 0},
		{"example.com:8080", "example.com", 8080},
		{"example.com:0", "example.com", 0},
		{"example.com:99999", "example.com", 0},
		{"example.com:abc", "example.com", 0},
		{"127.0.0.1:443", "127.0.0.1", 443},
		{"[::1]:8080", "::1", 8080},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"[::1]", "::1", 0},
		{"[unclosed", "[unclosed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotHost, gotPort := splitHostPort(tt.in)
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)",
					tt.in, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}

// TestSplitPathAndQuery covers the path/query splitter.
func TestSplitPathAndQuery(t *testing.T) {
	tests := []struct {
		in, wantPath, wantQuery string
	}{
		{"", "", ""},
		{"/foo", "/foo", ""},
		{"/foo?x=1", "/foo", "x=1"},
		{"/foo?x=1&y=2", "/foo", "x=1&y=2"},
		{"/foo?", "/foo", ""},
		{"?onlyquery", "", "onlyquery"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			p, q := splitPathAndQuery(tt.in)
			if p != tt.wantPath || q != tt.wantQuery {
				t.Errorf("splitPathAndQuery(%q) = (%q,%q), want (%q,%q)",
					tt.in, p, q, tt.wantPath, tt.wantQuery)
			}
		})
	}
}

// TestParseHTTPRequest_SplitsHostAndPath verifies the front-door parser splits
// ":authority" into Host+Port and ":path" into Path+Query.
func TestParseHTTPRequest_SplitsHostAndPath(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com:8443",
		":path":      "/v1/chat?x=1&y=2",
		":method":    "POST",
	})
	if info.Host != "api.example.com" {
		t.Errorf("expected host=api.example.com, got %q", info.Host)
	}
	if info.Port != 8443 {
		t.Errorf("expected port=8443, got %d", info.Port)
	}
	if info.Path != "/v1/chat" {
		t.Errorf("path should NOT include query, got %q", info.Path)
	}
	if info.Query.Get("x") != "1" || info.Query.Get("y") != "2" {
		t.Errorf("expected x=1 y=2, got %v", info.Query)
	}

	// Falls back to "host" header when :authority is absent.
	info2 := parseHTTPRequest(context.Background(), map[string]string{
		"host":    "fallback.example.com:1234",
		":path":   "/p",
		":method": "GET",
	})
	if info2.Host != "fallback.example.com" || info2.Port != 1234 {
		t.Errorf("expected host=fallback.example.com:1234, got %q:%d", info2.Host, info2.Port)
	}
	if info2.Query != nil {
		t.Errorf("expected nil query for path with no '?', got %v", info2.Query)
	}

	// Empty headers map yields zero HTTPRequest (with non-nil Headers map).
	info3 := parseHTTPRequest(context.Background(), map[string]string{})
	if info3.Host != "" || info3.Path != "" || info3.Method != "" || info3.Port != 0 {
		t.Errorf("expected empty info, got %+v", info3)
	}
}

// TestParseHTTPRequest_MalformedQuery verifies that an unparsable query
// string does not panic; the DEBUG log branch is exercised but the returned
// Query may be empty or partial.
func TestParseHTTPRequest_MalformedQuery(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat?%zz",
		":method":    "GET",
	})
	if info.Path != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", info.Path)
	}
}

// TestParseHTTPRequest_ExtractsScheme verifies that the :scheme pseudo-header
// is propagated to HTTPRequest.Scheme.
func TestParseHTTPRequest_ExtractsScheme(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat",
		":method":    "GET",
		":scheme":    "https",
	})
	if info.Scheme != "https" {
		t.Errorf("expected Scheme 'https', got %q", info.Scheme)
	}

	info2 := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat",
		":method":    "GET",
	})
	if info2.Scheme != "" {
		t.Errorf("expected empty Scheme when :scheme absent, got %q", info2.Scheme)
	}
}

// TestParseHTTPRequest_InfersPortFromScheme verifies that an authority
// without an explicit port falls back to the scheme's default (80/443).
func TestParseHTTPRequest_InfersPortFromScheme(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		scheme    string
		wantPort  int32
	}{
		{"http scheme infers 80", "api.example.com", "http", 80},
		{"HTTPS scheme infers 443 (case-insensitive)", "api.example.com", "HTTPS", 443},
		{"explicit port overrides http inference", "api.example.com:8080", "http", 8080},
		{"explicit port overrides https inference", "api.example.com:9443", "https", 9443},
		{"unknown scheme leaves Port=0", "api.example.com", "ftp", 0},
		{"missing scheme leaves Port=0", "api.example.com", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := map[string]string{
				":authority": tt.authority,
				":path":      "/",
				":method":    "GET",
			}
			if tt.scheme != "" {
				h[":scheme"] = tt.scheme
			}
			info := parseHTTPRequest(context.Background(), h)
			if info.Port != tt.wantPort {
				t.Errorf("got Port=%d, want %d", info.Port, tt.wantPort)
			}
		})
	}
}

func TestNormalizeConnectUDPMasqueTargetRequiresRouteIdentity(t *testing.T) {
	headers := map[string]string{
		":authority":       "10.244.0.9:15008",
		":path":            "/.well-known/masque/udp/udp-echo.example.com/9000/",
		":method":          "CONNECT",
		":scheme":          "https",
		"capsule-protocol": "?1",
	}
	info := parseHTTPRequest(context.Background(), headers)
	if !normalizeConnectUDPMasqueTarget(&info, "connect-udp:udp-echo.example.com:9000") {
		t.Fatal("expected trusted CONNECT-UDP route to normalize")
	}

	if info.Host != "udp-echo.example.com" {
		t.Errorf("CONNECT-UDP Host = %q, want udp-echo.example.com", info.Host)
	}
	if info.Port != 9000 {
		t.Errorf("CONNECT-UDP Port = %d, want 9000", info.Port)
	}
	if info.Scheme != "udp" {
		t.Errorf("CONNECT-UDP Scheme = %q, want udp", info.Scheme)
	}
	if info.Method != "CONNECT" {
		t.Errorf("CONNECT-UDP Method = %q, want CONNECT", info.Method)
	}
	if info.Path != "" {
		t.Errorf("CONNECT-UDP Path = %q, want empty application path", info.Path)
	}

	spoofed := parseHTTPRequest(context.Background(), headers)
	if normalizeConnectUDPMasqueTarget(&spoofed, "default") {
		t.Fatal("untrusted ordinary HTTP route must not normalize a MASQUE-looking path")
	}
	if spoofed.Host != "10.244.0.9" || spoofed.Port != 15008 {
		t.Fatalf("spoofed destination = %s:%d, want 10.244.0.9:15008", spoofed.Host, spoofed.Port)
	}
}

func TestNormalizeConnectUDPMasqueTargetAcceptsEnvoyUpgradeForm(t *testing.T) {
	headers := map[string]string{
		":authority":       "10.244.0.9:15008",
		":path":            "/.well-known/masque/udp/udp-echo.example.com/9000/",
		":method":          "GET",
		":scheme":          "https",
		"upgrade":          "connect-udp",
		"capsule-protocol": "?1",
	}
	info := parseHTTPRequest(context.Background(), headers)
	if !normalizeConnectUDPMasqueTarget(&info, "connect-udp:udp-echo.example.com:9000") {
		t.Fatal("expected Envoy's extended-CONNECT upgrade form to normalize")
	}
	if info.Method != "CONNECT" || info.Scheme != "udp" || info.Host != "udp-echo.example.com" || info.Port != 9000 {
		t.Fatalf("normalized request = %+v", info)
	}

	delete(headers, "upgrade")
	ordinaryGET := parseHTTPRequest(context.Background(), headers)
	if normalizeConnectUDPMasqueTarget(&ordinaryGET, "connect-udp:udp-echo.example.com:9000") {
		t.Fatal("ordinary GET must not normalize as CONNECT-UDP")
	}
}

// TestInferPortFromScheme exercises the helper directly.
func TestInferPortFromScheme(t *testing.T) {
	cases := map[string]int32{
		"http":  80,
		"HTTP":  80,
		"https": 443,
		"Https": 443,
		"ftp":   0,
		"":      0,
	}
	for in, want := range cases {
		if got := inferPortFromScheme(in); got != want {
			t.Errorf("inferPortFromScheme(%q) = %d, want %d", in, got, want)
		}
	}
}
