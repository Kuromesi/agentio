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
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The fixture records what crossed each real HTTP hop. Tests read observations
// through port-forwarding, independently of the gateway under test.
type calloutObservation struct {
	Invocations   map[string]json.RawMessage `json:"invocations"`
	OriginCalls   int                        `json:"originCalls"`
	OriginBody    string                     `json:"originBody"`
	OriginHeaders http.Header                `json:"originHeaders"`
}

type calloutFixture struct {
	mu           sync.Mutex
	observations map[string]*calloutObservation
}

func newCalloutFixture() http.Handler {
	f := &calloutFixture{observations: map[string]*calloutObservation{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /callout/{mode}", f.callout)
	mux.HandleFunc("POST /origin/{name}", f.origin)
	mux.HandleFunc("GET /observations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := json.NewEncoder(w).Encode(f.observations[r.URL.Query().Get("path")]); err != nil {
			http.Error(w, err.Error(), 500)
		}
	})
	return mux
}

func (f *calloutFixture) observation(path string) *calloutObservation {
	observation := f.observations[path]
	if observation == nil {
		observation = &calloutObservation{Invocations: map[string]json.RawMessage{}}
		f.observations[path] = observation
	}
	return observation
}

func (f *calloutFixture) callout(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var invocation struct {
		Version string `json:"version"`
		Phase   string `json:"phase"`
		Request struct {
			Path string  `json:"path"`
			Body *string `json:"body"`
		} `json:"request"`
		Response *struct {
			Body *string `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(
		raw,
		&invocation,
	); err != nil || invocation.Version != "0.1" ||
		(invocation.Phase != "request" && invocation.Phase != "response") {
		http.Error(w, "invalid invocation", 400)
		return
	}
	f.mu.Lock()
	f.observation(invocation.Request.Path).Invocations[invocation.Phase] = raw
	f.mu.Unlock()
	var decision any
	switch r.PathValue("mode") {
	case "error":
		http.Error(w, "scanner unavailable", 500)
		return
	case "deny":
		decision = map[string]any{
			"version":  "0.1",
			"action":   "respond",
			"response": map[string]any{"statusCode": 403, "body": "denied by callout"},
		}
	case "mutate":
		mutation := map[string]any{
			"headers": []any{
				map[string]any{"operation": "set", "name": "x-callout-" + invocation.Phase, "value": "scanned"},
			},
		}
		if invocation.Phase == "request" && invocation.Request.Body != nil ||
			invocation.Phase == "response" && invocation.Response != nil && invocation.Response.Body != nil {
			mutation["body"] = "rewritten-" + invocation.Phase
		}
		decision = map[string]any{"version": "0.1", "action": "continue", invocation.Phase: mutation}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (f *calloutFixture) origin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	f.mu.Lock()
	observation := f.observation(r.URL.Path)
	observation.OriginCalls++
	observation.OriginBody = string(body)
	observation.OriginHeaders = r.Header.Clone()
	f.mu.Unlock()
	w.Header().Set("X-Origin-Policy", r.Header.Get("X-Policy"))
	w.Header().Set("X-Public", "public")
	w.Header().Set("Set-Cookie", "origin-secret")
	if _, err := io.Copy(w, strings.NewReader("12345")); err != nil {
		return
	}
}

func serveHTTPCallout(port int) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           newCalloutFixture(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}
