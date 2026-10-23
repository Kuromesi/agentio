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
	"net"
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
	handler      http.Handler
	release      chan struct{}
	releaseOnce  sync.Once
	transport    map[string]*calloutConnection
	refused      int
	mu           sync.Mutex
	observations map[string]*calloutObservation
}

func newCalloutFixture() *calloutFixture {
	f := &calloutFixture{
		observations: map[string]*calloutObservation{},
		release:      make(chan struct{}),
		transport:    map[string]*calloutConnection{},
	}
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
	f.handler = mux
	return f
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

// Connection observations let E2E assert draining, not just successful responses.
type calloutConnection struct {
	Path     string
	Protocol int
	Active   int
	Peak     int
	Calls    int
	Closed   bool
	release  chan struct{}
}

func (f *calloutFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/transport" {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := json.NewEncoder(w).Encode(struct {
			Connections map[string]*calloutConnection
			Refused     int
		}{f.transport, f.refused}); err != nil {
			http.Error(w, err.Error(), 500)
		}
		return
	}
	if r.URL.Path == "/release" && r.Method == http.MethodPost {
		if addr := r.URL.Query().Get("connection"); addr != "" {
			f.mu.Lock()
			defer f.mu.Unlock()
			c := f.transport[addr]
			if c == nil {
				http.Error(w, "unknown connection", http.StatusNotFound)
				return
			}
			if c.release != nil {
				close(c.release)
				c.release = nil
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.releaseOnce.Do(func() { close(f.release) })
		w.WriteHeader(204)
		return
	}
	if r.Method != http.MethodPost || strings.HasPrefix(r.URL.Path, "/origin/") {
		f.handler.ServeHTTP(w, r)
		return
	}
	f.mu.Lock()
	c := f.transport[r.RemoteAddr]
	if c == nil {
		c = &calloutConnection{Protocol: r.ProtoMajor, release: make(chan struct{})}
		f.transport[r.RemoteAddr] = c
	}
	c.Path = r.URL.Path
	c.Active++
	c.Calls++
	c.Peak = max(c.Peak, c.Active)
	release := c.release
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		c.Active--
		f.mu.Unlock()
	}()
	if r.URL.Path == "/hold" {
		select {
		case <-f.release:
		case <-r.Context().Done():
			return
		}
		r.URL.Path = "/continue"
	}
	if strings.HasPrefix(r.URL.Path, "/controlled/") {
		if release != nil {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		r.URL.Path = "/continue"
	}
	f.handler.ServeHTTP(w, r)
}
func (f *calloutFixture) observeConnections(server *http.Server) {
	server.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			f.mu.Lock()
			if record := f.transport[c.RemoteAddr().String()]; record != nil {
				record.Closed = true
			}
			f.mu.Unlock()
		}
	}
	server.HTTP2.CountError = func(kind string) {
		if kind == "stream_REFUSED_STREAM_over_max_streams_race" {
			f.mu.Lock()
			f.refused++
			f.mu.Unlock()
		}
	}
}
