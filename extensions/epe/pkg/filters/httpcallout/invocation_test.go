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
	"maps"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
)

func testUnitID() filter.UnitID {
	return filter.UnitID{Scope: "default/profile", Name: "inspect", Ordinal: 2}
}

// testStream mirrors what the engine hands a filter: a peer with a token that
// must never leave the mesh, and a request whose parsed Query disagrees with
// RawQuery so a builder reading the wrong one is visible.
func testStream() *filter.Stream {
	return &filter.Stream{
		Peer: filter.Peer{
			Pod:    types.NamespacedName{Namespace: "default", Name: "agent-0"},
			IP:     "10.0.0.8",
			Labels: map[string]string{"app": "agent"},
			Token:  &filter.SandboxToken{AccessToken: "secret-token", SandboxClientID: "client-1"},
		},
		RequestID: "req-123",
		Request: httpreq.HTTPRequest{
			Host:     "api.example.com",
			Port:     443,
			Path:     "/v1/run",
			Query:    url.Values{"debug": []string{"true"}},
			RawQuery: "debug=true;trace=1",
			Method:   "POST",
			Scheme:   "https",
			Headers: map[string]string{
				"content-type":  "application/json",
				"x-tenant":      "demo",
				"authorization": "Bearer caller-credential",
				"cookie":        "session=abc",
				"x-request-id":  "req-123",
			},
		},
		Response: httpreq.HTTPResponse{
			Status: 201,
			Headers: map[string]string{
				"content-type": "text/plain",
				"x-upstream":   "demo",
			},
		},
	}
}

func testConfig(t *testing.T, cfg Config) Config {
	t.Helper()
	cfg.Endpoint = "https://scanner.example.com/inspect"
	effective, err := cfg.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return effective
}

func TestBuildRequestInvocationMapsEveryField(t *testing.T) {
	cfg := testConfig(t, Config{Request: true})
	st := testStream()

	inv, err := buildRequestInvocation(cfg, testUnitID(), st, filter.Body{Bytes: []byte(`{"input":"hi"}`), Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}

	if inv.Version != ProtocolVersion || inv.Phase != PhaseRequest {
		t.Errorf("version/phase = %q/%q, want %q/%q", inv.Version, inv.Phase, ProtocolVersion, PhaseRequest)
	}
	wantSource := SourceContext{
		Namespace: "default",
		Pod:       "agent-0",
		IP:        "10.0.0.8",
		Labels:    map[string]string{"app": "agent"},
	}
	if !reflect.DeepEqual(inv.Source, wantSource) {
		t.Errorf("source = %#v, want %#v", inv.Source, wantSource)
	}
	wantPolicy := PolicyContext{Scope: "default/profile", Rule: "inspect", Ordinal: 2}
	if inv.Policy != wantPolicy {
		t.Errorf("policy = %#v, want %#v", inv.Policy, wantPolicy)
	}
	if inv.Response != nil {
		t.Errorf("request-phase invocation carried a response: %#v", inv.Response)
	}

	got := *inv.Request
	got.Body = nil
	want := HTTPRequest{
		ID:          "req-123",
		Method:      "POST",
		Scheme:      "https",
		Host:        "api.example.com",
		Port:        443,
		Path:        "/v1/run",
		RawQuery:    "debug=true;trace=1",
		ContentType: "application/json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("request view = %#v, want %#v", got, want)
	}
	if inv.Request.Body == nil || *inv.Request.Body != `{"input":"hi"}` {
		t.Errorf("request body = %#v, want the buffered bytes as a UTF-8 string", inv.Request.Body)
	}
}

// TestBuildRequestInvocationSendsAPresentEmptyBody pins that a bodyless request
// still carries a body pointer: Invocation.Validate requires one, and the
// callout must be able to tell "no body" from "field absent".
func TestBuildRequestInvocationSendsAPresentEmptyBody(t *testing.T) {
	cfg := testConfig(t, Config{Request: true})
	inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	if inv.Request.Body == nil || *inv.Request.Body != "" {
		t.Fatalf("request body = %#v, want a pointer to the empty string", inv.Request.Body)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
}

func TestBuildRequestInvocationHeaderModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  RequestHeadersConfig
		want map[string]string
	}{
		{
			name: "none omits every header",
			cfg:  RequestHeadersConfig{Mode: RequestHeadersNone},
			want: nil,
		},
		{
			name: "allowlist forwards only the named headers",
			cfg:  RequestHeadersConfig{Mode: RequestHeadersAllowlist, Allowlist: []string{"X-Tenant", "x-absent"}},
			want: map[string]string{"x-tenant": "demo"},
		},
		{
			// The never-forward rule is the whole point of this mode: a
			// third-party endpoint outside the mesh must not receive the
			// caller's credentials just because the operator asked for "all".
			name: "all forwards everything except credentials",
			cfg:  RequestHeadersConfig{Mode: RequestHeadersAll},
			want: map[string]string{
				"content-type": "application/json",
				"x-tenant":     "demo",
				"x-request-id": "req-123",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, Config{Request: true, RequestHeaders: tc.cfg})
			inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Complete: true})
			if err != nil {
				t.Fatalf("buildRequestInvocation: %v", err)
			}
			if !reflect.DeepEqual(inv.Request.Headers, tc.want) {
				t.Fatalf("forwarded headers = %#v, want %#v", inv.Request.Headers, tc.want)
			}
		})
	}
}

// TestBuildRequestInvocationNeverAliasesStreamHeaders pins that the builder owns
// its map: st.Request.Headers is shared with every other filter on the path.
func TestBuildRequestInvocationNeverAliasesStreamHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Request: true, RequestHeaders: RequestHeadersConfig{Mode: RequestHeadersAll}})
	st := testStream()
	before := maps.Clone(st.Request.Headers)

	inv, err := buildRequestInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	inv.Request.Headers["x-injected"] = "value"
	if !reflect.DeepEqual(st.Request.Headers, before) {
		t.Fatalf("stream headers = %#v, want them untouched at %#v", st.Request.Headers, before)
	}
}

func TestBuildResponseInvocationOmitsTheRequestBodyAndHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Response: true, RequestHeaders: RequestHeadersConfig{Mode: RequestHeadersAll}})
	st := testStream()

	inv, err := buildResponseInvocation(cfg, testUnitID(), st, filter.Body{Bytes: []byte("response text"), Complete: true})
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
	if inv.Phase != PhaseResponse {
		t.Errorf("phase = %q, want %q", inv.Phase, PhaseResponse)
	}
	if inv.Request.Body != nil {
		t.Errorf("response-phase request view carried a body: %#v", *inv.Request.Body)
	}
	// Header forwarding config governs the request phase only; the response
	// phase never forwards request headers regardless of mode.
	if inv.Request.Headers != nil {
		t.Errorf("response-phase request view carried headers: %#v", inv.Request.Headers)
	}
	if inv.Request.ID != "req-123" || inv.Request.Method != "POST" || inv.Request.RawQuery != "debug=true;trace=1" {
		t.Errorf("correlation fields lost: %#v", *inv.Request)
	}

	want := HTTPResponse{
		StatusCode:  201,
		ContentType: "text/plain",
		Headers:     map[string]string{"content-type": "text/plain", "x-upstream": "demo"},
		Body:        "response text",
	}
	if !reflect.DeepEqual(*inv.Response, want) {
		t.Errorf("response view = %#v, want %#v", *inv.Response, want)
	}
}

func TestBuildResponseInvocationNeverAliasesStreamHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Response: true})
	st := testStream()
	before := maps.Clone(st.Response.Headers)

	inv, err := buildResponseInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	inv.Response.Headers["x-injected"] = "value"
	if !reflect.DeepEqual(st.Response.Headers, before) {
		t.Fatalf("stream headers = %#v, want them untouched at %#v", st.Response.Headers, before)
	}
}

// TestBuildResponseInvocationAlwaysCarriesResponseHeaders pins the never-nil
// contract Invocation.Validate enforces, for an upstream that sent none.
func TestBuildResponseInvocationAlwaysCarriesResponseHeaders(t *testing.T) {
	cfg := testConfig(t, Config{Response: true})
	st := testStream()
	st.Response.Headers = nil

	inv, err := buildResponseInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildResponseInvocation: %v", err)
	}
	if inv.Response.Headers == nil {
		t.Fatal("response headers were nil, which Invocation.Validate rejects")
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("built invocation failed Validate: %v", err)
	}
}

// TestBuildInvocationRejectsOversizedBody pins that the limit is a failure, not
// a truncation: asking a scanner to approve content it never saw is worse than
// failing the callout and letting FailOpen decide.
func TestBuildInvocationRejectsOversizedBody(t *testing.T) {
	cfg := testConfig(t, Config{Request: true, Response: true, MaxBodyBytes: 8})
	body := filter.Body{Bytes: []byte("123456789"), Complete: true}

	for _, tc := range []struct {
		name  string
		build func() (Invocation, error)
	}{
		{
			name:  "request",
			build: func() (Invocation, error) { return buildRequestInvocation(cfg, testUnitID(), testStream(), body) },
		},
		{
			name:  "response",
			build: func() (Invocation, error) { return buildResponseInvocation(cfg, testUnitID(), testStream(), body) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := tc.build()
			if err == nil {
				t.Fatalf("build succeeded with %#v, want an error naming the limit", inv)
			}
			if !strings.Contains(err.Error(), "8") {
				t.Errorf("error = %q, want it to name the configured limit", err.Error())
			}
			if inv.Request != nil || inv.Response != nil {
				t.Errorf("a rejected build still returned content: %#v", inv)
			}
		})
	}

	t.Run("at the limit", func(t *testing.T) {
		inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Bytes: []byte("12345678"), Complete: true})
		if err != nil {
			t.Fatalf("a body exactly at the limit was rejected: %v", err)
		}
		if *inv.Request.Body != "12345678" {
			t.Fatalf("body = %q, want it intact", *inv.Request.Body)
		}
	})
}

func TestBuildInvocationRejectsNonUTF8Body(t *testing.T) {
	cfg := testConfig(t, Config{Request: true, Response: true})
	body := filter.Body{Bytes: []byte{0xff, 0xfe}, Complete: true}

	if _, err := buildRequestInvocation(cfg, testUnitID(), testStream(), body); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "utf-8") {
		t.Errorf("request build error = %v, want one naming UTF-8", err)
	}
	if _, err := buildResponseInvocation(cfg, testUnitID(), testStream(), body); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "utf-8") {
		t.Errorf("response build error = %v, want one naming UTF-8", err)
	}
}

// TestBuildInvocationNeverForwardsTheSandboxToken is a standing guard rather
// than a behaviour test: SourceContext has no token field today, and this fails
// loudly if one is ever added and populated.
func TestBuildInvocationNeverForwardsTheSandboxToken(t *testing.T) {
	cfg := testConfig(t, Config{Request: true, RequestHeaders: RequestHeadersConfig{Mode: RequestHeadersAll}})
	st := testStream()

	inv, err := buildRequestInvocation(cfg, testUnitID(), st, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	rendered := marshalJSONObject(t, inv)
	raw, ok := rendered["source"].(map[string]any)
	if !ok {
		t.Fatalf("source = %#v, want an object", rendered["source"])
	}
	for key := range raw {
		if strings.Contains(strings.ToLower(key), "token") {
			t.Errorf("source context exposed %q", key)
		}
	}
	for _, value := range inv.Request.Headers {
		if strings.Contains(value, st.Peer.Token.AccessToken) {
			t.Errorf("a forwarded header carried the sandbox access token: %q", value)
		}
	}
}
