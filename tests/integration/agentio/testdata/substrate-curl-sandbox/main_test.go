// Copyright 2026 The Kruise Authors.
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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExecutesCurlForHTTPURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inside-sandbox" {
			t.Fatalf("upstream path = %q, want /inside-sandbox", r.URL.Path)
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("curl-reached-upstream"))
	}))
	t.Cleanup(upstream.Close)

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"url":"`+upstream.URL+`/inside-sandbox"}`))
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusTeapot, response.Body.String())
	}
	var got struct {
		StatusCode int    `json:"statusCode"`
		Body       string `json:"body"`
		Execution  struct {
			Binary string   `json:"binary"`
			Argv   []string `json:"argv"`
		} `json:"execution"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.StatusCode != http.StatusTeapot || got.Body != "curl-reached-upstream" {
		t.Fatalf("upstream response = (%d, %q), want (%d, %q)", got.StatusCode, got.Body, http.StatusTeapot, "curl-reached-upstream")
	}
	if got.Execution.Binary != "/usr/bin/curl" {
		t.Fatalf("curl binary = %q, want /usr/bin/curl", got.Execution.Binary)
	}
	if len(got.Execution.Argv) == 0 || got.Execution.Argv[len(got.Execution.Argv)-1] != upstream.URL+"/inside-sandbox" {
		t.Fatalf("curl argv = %q, want target URL as final argument", got.Execution.Argv)
	}
}

func TestHandlerRejectsNonHTTPURL(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"url":"file:///etc/passwd"}`))
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "scheme must be http or https") {
		t.Fatalf("body = %q, want scheme validation error", response.Body.String())
	}
}

func TestHandlerExecutesCurlAfterIncomingContextIsCanceled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("curl-completed-after-caller-canceled"))
	}))
	t.Cleanup(upstream.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"url":"`+upstream.URL+`"}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "curl-completed-after-caller-canceled") {
		t.Fatalf("body = %q, want completed curl response", response.Body.String())
	}
}
