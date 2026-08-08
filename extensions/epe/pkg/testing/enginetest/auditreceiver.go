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

package enginetest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ReceivedRequest is one HTTP request captured by the AuditReceiver.
type ReceivedRequest struct {
	Method string
	// URL is the request URI as received (path + query).
	URL    string
	Header http.Header
	Body   []byte
}

func (r ReceivedRequest) contains(marker string) bool {
	if strings.Contains(r.URL, marker) || strings.Contains(string(r.Body), marker) {
		return true
	}
	for _, values := range r.Header {
		for _, v := range values {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	return false
}

// AuditReceiver is an in-process HTTP endpoint for audit webhook targets.
// It records every request (before applying any injected fault response)
// and supports marker-based waiting, mirroring the E2E audit-receiver
// pattern without log scraping.
type AuditReceiver struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []ReceivedRequest
	waiters  []chan struct{}
	status   int
	respBody string
}

// NewAuditReceiver starts the receiver and closes it on test cleanup.
func NewAuditReceiver(t testing.TB) *AuditReceiver {
	t.Helper()
	a := &AuditReceiver{status: http.StatusOK}
	a.server = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.server.Close)
	return a
}

func (a *AuditReceiver) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	a.mu.Lock()
	a.requests = append(a.requests, ReceivedRequest{
		Method: req.Method,
		URL:    req.URL.RequestURI(),
		Header: req.Header.Clone(),
		Body:   body,
	})
	for _, waiter := range a.waiters {
		close(waiter)
	}
	a.waiters = nil
	status := a.status
	respBody := a.respBody
	a.mu.Unlock()

	w.WriteHeader(status)
	if respBody != "" {
		_, _ = w.Write([]byte(respBody))
	}
}

// URL returns the receiver base URL joined with path. The path may contain
// audit URL template expressions; they are rendered by the webhook sink.
func (a *AuditReceiver) URL(path string) string {
	if path == "" {
		return a.server.URL
	}
	return a.server.URL + "/" + strings.TrimPrefix(path, "/")
}

// SetResponse makes the receiver answer every subsequent request with the
// given status and body, while still recording the request. Use it to
// exercise http_error handling in the dispatcher.
func (a *AuditReceiver) SetResponse(status int, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = status
	a.respBody = body
}

// Requests returns a snapshot of everything received so far.
func (a *AuditReceiver) Requests() []ReceivedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ReceivedRequest, len(a.requests))
	copy(out, a.requests)
	return out
}

// Matching returns the received requests whose URL, headers, or body
// contain marker.
func (a *AuditReceiver) Matching(marker string) []ReceivedRequest {
	var out []ReceivedRequest
	for _, r := range a.Requests() {
		if r.contains(marker) {
			out = append(out, r)
		}
	}
	return out
}

// WaitFor blocks until a request containing marker arrives, without
// polling: the receiver broadcasts on every captured request.
func (a *AuditReceiver) WaitFor(t testing.TB, marker string, timeout time.Duration) ReceivedRequest {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		a.mu.Lock()
		for _, r := range a.requests {
			if r.contains(marker) {
				a.mu.Unlock()
				return r
			}
		}
		waiter := make(chan struct{})
		a.waiters = append(a.waiters, waiter)
		a.mu.Unlock()

		select {
		case <-waiter:
		case <-deadline.C:
			t.Fatalf("no audit request containing %q arrived within %v (received=%d)", marker, timeout, len(a.Requests()))
			return ReceivedRequest{}
		}
	}
}

// AssertAbsent fails when any received request contains marker. Sound in
// synchronous audit mode, where delivery completes before the request
// handler returns; in buffered mode drain the dispatcher first.
func (a *AuditReceiver) AssertAbsent(t testing.TB, marker string) {
	t.Helper()
	if hits := a.Matching(marker); len(hits) > 0 {
		t.Fatalf("audit receiver unexpectedly captured %d request(s) containing %q: %+v", len(hits), marker, hits)
	}
}
