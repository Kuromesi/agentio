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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// calloutInvocation builds a valid request-phase invocation for client tests.
func calloutInvocation(t *testing.T) Invocation {
	t.Helper()
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
	inv, err := buildRequestInvocation(cfg, testUnitID(), testStream(), filter.Body{Bytes: []byte("body"), Complete: true})
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	return inv
}

// decisionFor is what a well-behaved endpoint answers with.
func decisionFor(inv Invocation) Decision {
	return Decision{
		Version:   ProtocolVersion,
		Phase:     inv.Phase,
		RequestID: inv.Request.ID,
		Action:    actionPtr(ActionContinue),
	}
}

func serveDecision(t *testing.T, handler http.HandlerFunc) (Config, *HTTPClient) {
	t.Helper()
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r.WithContext(withServerShutdown(r.Context(), done)))
	}))
	t.Cleanup(server.Close)
	// Registered after server.Close so it runs first: Cleanup is LIFO, and
	// Server.Close waits for in-flight handlers. Abandoning a request
	// client-side does not cancel the handler's context, so a handler parked on
	// Done would deadlock Close unless this releases it first.
	t.Cleanup(func() { close(done) })

	cfg, err := Config{Endpoint: server.URL, Request: &PhaseConfig{Body: true}}.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return cfg, NewHTTPClient()
}

// withServerShutdown makes the handler's Done fire at test cleanup as well as on
// real request cancellation.
func withServerShutdown(parent context.Context, done <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
		}
		cancel()
	}()
	return ctx
}

func TestHTTPClientPostsTheInvocationAsJSON(t *testing.T) {
	inv := calloutInvocation(t)
	var (
		gotMethod      string
		gotContentType string
		gotAccept      string
		gotPath        string
		gotBody        Invocation
	)
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_ = json.NewEncoder(w).Encode(decisionFor(inv))
	})

	got, err := client.Call(context.Background(), cfg, inv)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !reflect.DeepEqual(got, decisionFor(inv)) {
		t.Errorf("decision = %#v, want %#v", got, decisionFor(inv))
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotPath != "/" {
		t.Errorf("path = %q, want the endpoint path", gotPath)
	}
	if !reflect.DeepEqual(gotBody, inv) {
		t.Errorf("decoded invocation = %#v, want %#v", gotBody, inv)
	}
}

// TestHTTPClientHonoursThePerCallTimeout pins that Config.Timeout, which is
// per-unit, actually bounds one call. A shared http.Client.Timeout cannot
// express it, so the client must derive a context per call.
func TestHTTPClientHonoursThePerCallTimeout(t *testing.T) {
	inv := calloutInvocation(t)
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	cfg.Timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := client.Call(context.Background(), cfg, inv)
	if err == nil {
		t.Fatal("Call succeeded against a hanging endpoint, want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Call took %v, want it bounded by the per-call timeout", elapsed)
	}
	assertHidesEndpointBody(t, err, cfg.Endpoint, "")
}

func TestHTTPClientRejectsNon2xx(t *testing.T) {
	inv := calloutInvocation(t)
	const leaked = "internal scanner stack trace at /opt/scanner/main.py"
	for _, status := range []int{http.StatusNoContent, http.StatusMovedPermanently, http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
				if status == http.StatusNoContent {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(leaked))
			})
			_, err := client.Call(context.Background(), cfg, inv)
			if status == http.StatusNoContent {
				// 204 is 2xx but carries no decision; it must still fail.
				if err == nil {
					t.Fatal("Call accepted an empty 204, want an error")
				}
				return
			}
			if err == nil {
				t.Fatalf("Call accepted status %d, want an error", status)
			}
			if !strings.Contains(err.Error(), http.StatusText(status)) && !strings.Contains(err.Error(), "status") {
				t.Errorf("error = %q, want it to name the status", err.Error())
			}
			assertHidesEndpointBody(t, err, cfg.Endpoint, leaked)
		})
	}
}

func TestHTTPClientRejectsUnparseableBody(t *testing.T) {
	inv := calloutInvocation(t)
	const leaked = "<html>scanner-internal.corp.example.com is down</html>"
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(leaked))
	})

	_, err := client.Call(context.Background(), cfg, inv)
	if err == nil {
		t.Fatal("Call accepted a non-JSON body, want an error")
	}
	assertHidesEndpointBody(t, err, cfg.Endpoint, leaked)
}

// TestHTTPClientRejectsAnOversizedDecision pins that the read is bounded and
// that hitting the bound is an error rather than a parse of a truncated body: a
// truncated JSON that happened to parse would be a decision nobody sent.
func TestHTTPClientRejectsAnOversizedDecision(t *testing.T) {
	inv := calloutInvocation(t)
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		decision := decisionFor(inv)
		decision.Action = actionPtr(ActionRespond)
		status := 403
		padding := strings.Repeat("a", 4096)
		decision.Response = &ResponseMutation{StatusCode: &status, Body: &padding}
		_ = json.NewEncoder(w).Encode(decision)
	})
	cfg.MaxBodyBytes = 64

	_, err := client.Call(context.Background(), cfg, inv)
	if err == nil {
		t.Fatal("Call accepted a decision over the body limit, want an error")
	}
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("error = %q, want it to name the limit", err.Error())
	}
}

// TestHTTPClientDoesNotRetry pins the no-retry rule: a callout may have taken a
// side effect already, so a second attempt would double it.
func TestHTTPClientDoesNotRetry(t *testing.T) {
	inv := calloutInvocation(t)
	var calls atomic.Int32
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := client.Call(context.Background(), cfg, inv); err == nil {
		t.Fatal("Call succeeded, want an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("endpoint saw %d calls, want exactly 1", got)
	}
}

// TestHTTPClientDoesNotFollowRedirects pins that a 3xx is a failure rather than
// a hop to wherever the endpoint points: following one would let the configured
// endpoint redirect the invocation, body and all, to an unvalidated URL.
func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	inv := calloutInvocation(t)
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_ = json.NewEncoder(w).Encode(decisionFor(inv))
	}))
	t.Cleanup(target.Close)

	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	if _, err := client.Call(context.Background(), cfg, inv); err == nil {
		t.Fatal("Call followed a redirect, want an error")
	}
	if got := elsewhere.Load(); got != 0 {
		t.Fatalf("redirect target saw %d calls, want 0", got)
	}
}

func TestHTTPClientReportsATransportFailureWithoutTheEndpoint(t *testing.T) {
	inv := calloutInvocation(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close()

	cfg, err := Config{Endpoint: endpoint, Request: &PhaseConfig{Body: true}}.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	_, err = NewHTTPClient().Call(context.Background(), cfg, inv)
	if err == nil {
		t.Fatal("Call reached a closed listener, want an error")
	}
	assertHidesEndpointBody(t, err, endpoint, "")
}

func TestHTTPClientHonoursCallerCancellation(t *testing.T) {
	inv := calloutInvocation(t)
	cfg, client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	cfg.Timeout = 30 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := client.Call(ctx, cfg, inv); err == nil {
		t.Fatal("Call ignored the cancelled caller context, want an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Call took %v, want the caller's cancellation to win", elapsed)
	}
}

// assertHidesEndpointBody pins the hygiene rule from tokentransform's blockReply:
// a callout error is logged, but it must not name the endpoint or quote the
// remote's response text, because the framework-generated deny is what the
// untrusted client sees.
func assertHidesEndpointBody(t *testing.T, err error, endpoint, remoteText string) {
	t.Helper()
	if strings.Contains(err.Error(), endpoint) {
		t.Errorf("error = %q, want it to omit the endpoint URL %q", err.Error(), endpoint)
	}
	if remoteText != "" && strings.Contains(err.Error(), remoteText) {
		t.Errorf("error = %q, want it to omit the remote response text", err.Error())
	}
}
