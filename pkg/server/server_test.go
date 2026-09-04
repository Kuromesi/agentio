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

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/server/debug"
	"istio.io/istio/pkg/test"
)

func TestWithRunContextCancelsChildWhenRunReturns(t *testing.T) {
	want := errors.New("initialization failed")
	var child context.Context
	err := withRunContext(context.Background(), func(ctx context.Context) error {
		child = ctx
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("withRunContext() error = %v, want %v", err, want)
	}
	select {
	case <-child.Done():
	case <-time.After(time.Second):
		t.Fatal("child context remained active after run returned")
	}
}

func TestRunRejectsInvalidOptions(t *testing.T) {
	options := DefaultOptions()
	options.MonitoringAddress = ""

	if err := Run(context.Background(), options); err == nil {
		t.Fatal("Run() accepted invalid options")
	}
}

func TestRunStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, DefaultOptions())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}
}

func TestGRPCServerKeepaliveUsesConfiguredMaxConnectionAge(t *testing.T) {
	test.SetForTest(t, &features.MaxServerConnectionAge, 47*time.Minute)
	parameters := grpcServerKeepaliveParameters()
	if parameters.MaxConnectionAge != 47*time.Minute {
		t.Fatalf("MaxConnectionAge = %v, want 47m", parameters.MaxConnectionAge)
	}
}

func TestNewMonitoringHandlerRegistersConfigDebugHandlerWhenProvided(t *testing.T) {
	debugHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Debug-Handler", "reached")
		response.WriteHeader(http.StatusNoContent)
	})
	handler := newMonitoringHandler(func() bool { return true }, debugHandler)

	for _, path := range []string{debug.Path, debug.LoggingPath, debug.LoggingPath + "/krt"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent || response.Header().Get("X-Debug-Handler") != "reached" {
			t.Fatalf("%s debug response = %d headers=%v, want sentinel handler", path, response.Code, response.Header())
		}
	}
	for _, path := range []string{"/healthz", "/ready", "/metrics"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s response status = %d, want 200", path, response.Code)
		}
	}
}

func TestNewMonitoringHandlerOmitsConfigDebugHandlerWhenDisabled(t *testing.T) {
	handler := newMonitoringHandler(func() bool { return false }, nil)

	debugResponse := httptest.NewRecorder()
	handler.ServeHTTP(debugResponse, httptest.NewRequest(http.MethodGet, debug.Path, nil))
	if debugResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled debug response status = %d, want 404", debugResponse.Code)
	}
	loggingResponse := httptest.NewRecorder()
	handler.ServeHTTP(loggingResponse, httptest.NewRequest(http.MethodGet, debug.LoggingPath+"/krt", nil))
	if loggingResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled logging debug response status = %d, want 404", loggingResponse.Code)
	}
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health response status = %d, want 200", healthResponse.Code)
	}
	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready response status = %d, want 503", readyResponse.Code)
	}
}
