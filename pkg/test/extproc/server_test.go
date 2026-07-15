// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extproc

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func TestParseHeaderPairs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{name: "empty", in: "", want: map[string]string{}},
		{name: "normalizes keys", in: " X-Foo = one, x-BAR=two ", want: map[string]string{"x-foo": "one", "x-bar": "two"}},
		{name: "skips invalid pairs", in: "missing, =empty-key,valid=value", want: map[string]string{"valid": "value"}},
		{name: "last value wins", in: "x-test=first,x-test=second", want: map[string]string{"x-test": "second"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHeaderPairs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("parseHeaderPairs() = %v, want %v", got, tt.want)
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("parseHeaderPairs()[%q] = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestConfigFromEnvironmentDoesNotMutateDefaults(t *testing.T) {
	env := map[string]string{
		"REQUEST_HEADERS_TO_ADD":       "x-request=custom",
		"RESPONSE_HEADERS_TO_ADD":      "x-response=custom",
		"REQUEST_BODY_OVERRIDE_HEADER": "x-body-mode",
	}
	getenv := func(key string) string { return env[key] }

	first := ConfigFromEnvironment(getenv)
	second := ConfigFromEnvironment(func(string) string { return "" })

	if first.RequestHeadersToAdd["x-request"] != "custom" {
		t.Fatalf("custom request header missing: %v", first.RequestHeadersToAdd)
	}
	if first.ResponseHeadersToAdd["x-response"] != "custom" {
		t.Fatalf("custom response header missing: %v", first.ResponseHeadersToAdd)
	}
	if first.RequestBodyOverrideHeader != "x-body-mode" {
		t.Fatalf("override header = %q, want x-body-mode", first.RequestBodyOverrideHeader)
	}
	if _, found := second.RequestHeadersToAdd["x-request"]; found {
		t.Fatalf("default config was mutated: %v", second.RequestHeadersToAdd)
	}
	if second.RequestHeadersToAdd["x-ext-proc-header"] != "hello-to-asm" ||
		second.ResponseHeadersToAdd["x-ext-proc-header"] != "hello-from-asm" ||
		second.RequestBodyOverrideHeader != defaultRequestBodyOverrideHeader {
		t.Fatalf("unexpected defaults: %+v", second)
	}
}

func TestHandleRequestHeaders(t *testing.T) {
	server := NewServer(Config{
		RequestHeadersToAdd:       map[string]string{"x-added": "request"},
		ResponseHeadersToAdd:      map[string]string{},
		RequestBodyOverrideHeader: "x-body-mode",
	})
	req := &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: "x-body-mode", RawValue: []byte("BUFFERED")},
			{Key: "x-asm-clear-route-cache", RawValue: []byte("true")},
			{Key: "request-header-modifier", RawValue: []byte(`{"x-dynamic":"value"}`)},
		}},
	}}

	response := server.handleRequestHeaders(req)
	headers := response.GetRequestHeaders().Response
	if !headers.ClearRouteCache {
		t.Fatal("ClearRouteCache = false, want true")
	}
	if response.ModeOverride.GetRequestBodyMode().String() != "BUFFERED" {
		t.Fatalf("request body mode = %v, want BUFFERED", response.ModeOverride.GetRequestBodyMode())
	}
	got := headerMap(headers.HeaderMutation.SetHeaders)
	if got["x-added"] != "request" || got["x-dynamic"] != "value" {
		t.Fatalf("request mutations = %v", got)
	}
}

func TestHandleResponseHeadersAndBody(t *testing.T) {
	server := NewServer(Config{
		RequestHeadersToAdd:       map[string]string{},
		ResponseHeadersToAdd:      map[string]string{"x-added": "response"},
		RequestBodyOverrideHeader: "x-body-mode",
	})

	headers := server.handleResponseHeaders(&extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
	})
	got := headerMap(headers.GetResponseHeaders().Response.HeaderMutation.SetHeaders)
	if got["x-added"] != "response" {
		t.Fatalf("response mutations = %v", got)
	}

	body := server.handleRequestBody(&extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte("hello"), EndOfStream: true},
	})
	if body.GetRequestBody() == nil || body.GetRequestBody().Response == nil {
		t.Fatalf("request body response is incomplete: %v", body)
	}
}

func TestResponseForAllPhases(t *testing.T) {
	server := NewServer(Config{})
	tests := []struct {
		name    string
		request *extprocv3.ProcessingRequest
		check   func(*extprocv3.ProcessingResponse) bool
	}{
		{
			name: "request headers",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetRequestHeaders() != nil },
		},
		{
			name: "request body",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetRequestBody() != nil },
		},
		{
			name: "request trailers",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
				RequestTrailers: &extprocv3.HttpTrailers{},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetRequestTrailers() != nil },
		},
		{
			name: "response headers",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetResponseHeaders() != nil },
		},
		{
			name: "response body",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetResponseBody() != nil },
		},
		{
			name: "response trailers",
			request: &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
				ResponseTrailers: &extprocv3.HttpTrailers{},
			}},
			check: func(response *extprocv3.ProcessingResponse) bool { return response.GetResponseTrailers() != nil },
		},
		{
			name:    "unknown",
			request: &extprocv3.ProcessingRequest{},
			check:   func(response *extprocv3.ProcessingResponse) bool { return response.Response == nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if response := server.responseFor(tt.request); !tt.check(response) {
				t.Fatalf("unexpected response: %v", response)
			}
		})
	}
}

func TestBodyMode(t *testing.T) {
	tests := map[string]string{
		"BUFFERED":             "BUFFERED",
		"streamed":             "STREAMED",
		" BUFFERED_PARTIAL ":   "BUFFERED_PARTIAL",
		"FULL_DUPLEX_STREAMED": "STREAMED",
		"invalid":              "STREAMED",
	}
	for input, want := range tests {
		if got := bodyMode(input).String(); got != want {
			t.Errorf("bodyMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHeaderModifiers(t *testing.T) {
	if got := headerModifiers("modifier", nil); got != nil {
		t.Fatalf("nil headers returned %v", got)
	}
	invalid := &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: "modifier", Value: "not-json"},
	}}}
	if got := headerModifiers("modifier", invalid); got != nil {
		t.Fatalf("invalid JSON returned %v", got)
	}
	valid := &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: "Modifier", Value: `{"x-value":"from-value"}`},
	}}}
	if got := headerMap(headerModifiers("modifier", valid)); got["x-value"] != "from-value" {
		t.Fatalf("value header modifiers = %v", got)
	}
}

func headerMap(options []*corev3.HeaderValueOption) map[string]string {
	result := make(map[string]string, len(options))
	for _, option := range options {
		result[option.Header.Key] = string(option.Header.RawValue)
	}
	return result
}
