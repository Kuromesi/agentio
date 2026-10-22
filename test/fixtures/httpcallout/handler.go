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

// Package httpcallout provides a deterministic HTTPCallout protocol test endpoint.
package httpcallout

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	protocol "github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/pkg/log"
)

var logger = log.New("httpcallout-test")

// Handler supports /continue, /mutate, /respond, /status, /malformed,
// /oversize, /delay and /reset. Counters exclude health and stats requests.
type Handler struct {
	Calls    atomic.Int64
	Active   atomic.Int64
	Canceled atomic.Int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path == "/stats" {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).
			Encode(map[string]int64{"calls": h.Calls.Load(), "active": h.Active.Load(), "canceled": h.Canceled.Load()}); err != nil {
			logger.Debug("stats response interrupted", "error", err)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	switch r.URL.Path {
	case "/continue", "/mutate", "/respond", "/status", "/malformed", "/oversize", "/delay", "/reset":
	default:
		http.NotFound(w, r)
		return
	}
	delay := time.Duration(0)
	if r.URL.Path == "/delay" {
		var err error
		delay, err = time.ParseDuration(r.URL.Query().Get("duration"))
		if err != nil || delay < 0 || delay > time.Minute {
			http.Error(w, "duration must be 0..1m", 400)
			return
		}
	}
	var inv protocol.Invocation
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := decoder.Decode(&inv); err != nil {
		http.Error(w, "invalid invocation", 400)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one JSON document required", 400)
		return
	}
	if err := inv.Validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := h.respond(w, r, inv, delay); err != nil {
		logger.Debug("callout response interrupted", "error", err)
	}
}

func (h *Handler) respond(
	w http.ResponseWriter,
	r *http.Request,
	inv protocol.Invocation,
	delay time.Duration,
) error {
	h.Calls.Add(1)
	h.Active.Add(1)
	defer h.Active.Add(-1)
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			h.Canceled.Add(1)
			return nil
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/status":
		http.Error(w, "injected failure", 503)
		return nil
	case "/malformed":
		_, err := io.WriteString(w, `{"version":`)
		return err
	case "/oversize":
		_, err := io.WriteString(w, strings.Repeat(" ", (1<<20)+1))
		return err
	case "/reset":
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return nil
		}
		return conn.Close()
	}
	d := protocol.Decision{Version: protocol.ProtocolVersion}
	switch r.URL.Path {
	case "/mutate":
		value, body := "clean", "changed by callout"
		headers := []protocol.HeaderMutation{
			{Operation: protocol.HeaderSet, Name: "x-callout-verdict", Value: &value},
		}
		if inv.Phase == protocol.PhaseRequest {
			d.Request = &protocol.RequestMutation{Headers: headers, Body: &body}
		} else {
			d.Response = &protocol.ResponseMutation{Headers: headers, Body: &body}
		}
	case "/respond":
		action, status, body := protocol.ActionRespond, 403, "blocked by callout"
		d.Action = &action
		d.Response = &protocol.ResponseMutation{StatusCode: &status, Body: &body}
	}
	return json.NewEncoder(w).Encode(d)
}
