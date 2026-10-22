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
	"io"
	"net/http"
	"strings"
	"sync"

	protocol "github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/test/fixtures/httpcallout"
)

// The fixture records what crossed each real HTTP hop. Tests read observations
// through port-forwarding, independently of the gateway under test.
type calloutObservation struct {
	Invocations   map[string]protocol.Invocation `json:"invocations"`
	OriginCalls   int                            `json:"originCalls"`
	OriginBody    string                         `json:"originBody"`
	OriginHeaders http.Header                    `json:"originHeaders"`
}

type calloutFixture struct {
	mu           sync.Mutex
	observations map[string]*calloutObservation
}

func newCalloutFixture() http.Handler {
	f := &calloutFixture{observations: map[string]*calloutObservation{}}
	mux := http.NewServeMux()
	mux.Handle("/", &httpcallout.Handler{Observe: func(inv protocol.Invocation) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.observation(inv.Request.Path).Invocations[string(inv.Phase)] = inv
	}})
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
		observation = &calloutObservation{Invocations: map[string]protocol.Invocation{}}
		f.observations[path] = observation
	}
	return observation
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
