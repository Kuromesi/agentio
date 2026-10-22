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

func TestHTTPCalloutFixture(t *testing.T) {
	handler := newCalloutFixture()
	for _, tc := range []struct {
		mode, phase string
		status      int
	}{
		{"mutate", "request", 200}, {"mutate", "response", 200}, {"deny", "request", 200}, {"error", "request", 500},
	} {
		t.Run(tc.mode+"-"+tc.phase, func(t *testing.T) {
			raw := `{"version":"0.1","phase":"` + tc.phase + `","request":{"path":"/origin/test","body":null},"response":{"body":"12345"}}`
			response := httptest.NewRecorder()
			handler.ServeHTTP(
				response,
				httptest.NewRequest(http.MethodPost, "/callout/"+tc.mode, strings.NewReader(raw)),
			)
			if response.Code != tc.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if tc.status != 200 {
				return
			}
			var decision struct {
				Version string `json:"version"`
				Action  string `json:"action"`
				Request *struct {
					Body *string `json:"body"`
				} `json:"request"`
				Response *struct {
					Body   *string `json:"body"`
					Status int     `json:"statusCode"`
				} `json:"response"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
				t.Fatal(err)
			}
			if decision.Version != "0.1" {
				t.Fatal("missing protocol version")
			}
			if tc.mode == "deny" {
				if decision.Action != "respond" || decision.Response == nil || decision.Response.Status != 403 {
					t.Fatalf("deny=%+v", decision)
				}
			} else if tc.phase == "request" {
				if decision.Request == nil || decision.Request.Body != nil {
					t.Fatal("metadata-only request must not rewrite the body")
				}
			} else if decision.Response == nil || decision.Response.Body == nil || *decision.Response.Body != "rewritten-response" {
				t.Fatalf("response=%+v", decision)
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/origin/test", strings.NewReader("rewritten-request"))
	request.Header.Set("X-Policy", "test-profile")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Body.String() != "12345" || response.Header().Get("X-Origin-Policy") != "test-profile" {
		t.Fatalf("origin=%+v", response)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/observations?path=/origin/test", nil))
	var observation calloutObservation
	if err := json.Unmarshal(response.Body.Bytes(), &observation); err != nil {
		t.Fatal(err)
	}
	if len(observation.Invocations) != 2 || observation.OriginCalls != 1 ||
		observation.OriginBody != "rewritten-request" ||
		observation.OriginHeaders.Get("X-Policy") != "test-profile" {
		t.Fatalf("observation=%+v", observation)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/observations?path=/origin/never-reached", nil))
	body := response.Body.String()
	if strings.TrimSpace(body) != "null" {
		t.Fatalf("unreached origin must have no observation: %s", body)
	}
}
