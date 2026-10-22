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

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPCalloutObservation(t *testing.T) {
	handler := newCalloutFixture()
	raw := `{"version":"0.1","phase":"request","request":{"method":"POST","path":"/origin/test","body":"original"}}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader(raw)))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "changed by callout") {
		t.Fatalf("shared handler response: %d %s", response.Code, response.Body)
	}
	request := httptest.NewRequest(http.MethodPost, "/origin/test", strings.NewReader("changed by callout"))
	request.Header.Set("X-Policy", "test-profile")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Body.String() != "12345" || response.Header().Get("X-Origin-Policy") != "test-profile" {
		t.Fatalf("origin response: %s", response.Body)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/observations?path=/origin/test", nil))
	var observation calloutObservation
	if err := json.Unmarshal(response.Body.Bytes(), &observation); err != nil {
		t.Fatal(err)
	}
	invocation := observation.Invocations["request"]
	if invocation.Request == nil || invocation.Request.Body == nil || *invocation.Request.Body != "original" {
		t.Fatalf("observed invocation: %+v", invocation)
	}
	if observation.OriginCalls != 1 || observation.OriginBody != "changed by callout" ||
		observation.OriginHeaders.Get("X-Policy") != "test-profile" {
		t.Fatalf("observed origin: %+v", observation)
	}
}
