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

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLoggingLevelUpdates(t *testing.T) {
	level := zap.NewAtomicLevelAt(zapcore.Level(-2))
	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	initial := loggingRequest(h, http.MethodGet, "/debug/logging", "")
	assertLoggingResponse(t, initial, "2")

	for _, tc := range []struct {
		input string
		want  string
		level zapcore.Level
	}{
		{input: "4", want: "4", level: -4},
		{input: "5", want: "5", level: -5},
		{input: "127", want: "127", level: -127},
		{input: "0", want: "info", level: zapcore.InfoLevel},
		{input: "1", want: "debug", level: zapcore.DebugLevel},
		{input: " DEBUG ", want: "debug", level: zapcore.DebugLevel},
		{input: "info", want: "info", level: zapcore.InfoLevel},
		{input: "warn", want: "warn", level: zapcore.WarnLevel},
		{input: "error", want: "error", level: zapcore.ErrorLevel},
		{input: "dpanic", want: "dpanic", level: zapcore.DPanicLevel},
		{input: "panic", want: "panic", level: zapcore.PanicLevel},
		{input: "fatal", want: "fatal", level: zapcore.FatalLevel},
	} {
		t.Run(tc.input, func(t *testing.T) {
			response := loggingRequest(h, http.MethodPut, "/debug/logging", `{"level":"`+tc.input+`"}`)
			assertLoggingResponse(t, response, tc.want)
			if got := level.Level(); got != tc.level {
				t.Fatalf("logger level = %v, want %v", got, tc.level)
			}
			get := loggingRequest(h, http.MethodGet, "/debug/logging", "")
			assertLoggingResponse(t, get, tc.want)
			// GET's canonical representation can be sent back unchanged.
			roundTrip := loggingRequest(h, http.MethodPut, "/debug/logging", get.Body.String())
			assertLoggingResponse(t, roundTrip, tc.want)
		})
	}
}

func TestLoggingRejectsInvalidUpdatesWithoutChangingLevel(t *testing.T) {
	level := zap.NewAtomicLevelAt(zapcore.WarnLevel)
	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	for _, body := range []string{
		``, `{`, `null`, `[]`, `{}`, `{"level":null}`, `{"level":""}`, `{"level":4}`,
		`{"level":"verbose"}`, `{"level":"-1"}`, `{"level":"128"}`, `{"level":"256"}`,
		`{"level":"4.0"}`, `{"level":"999999999999999999999999"}`,
		`{"level":"4","unknown":true}`, `{"level":"4"} {}`, `{"level":"4"} trailing`,
		`{"level":"` + strings.Repeat("x", maxLoggingBodyBytes) + `"}`,
		`{"level":"4"}` + strings.Repeat(" ", maxLoggingBodyBytes),
	} {
		response := loggingRequest(h, http.MethodPut, "/debug/logging", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %.80q: status=%d, want 400", body, response.Code)
		}
		if level.Level() != zapcore.WarnLevel {
			t.Fatalf("invalid body %.80q changed level to %v", body, level.Level())
		}
		var result errorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error == "" {
			t.Fatalf("invalid error response: %s (%v)", response.Body.String(), err)
		}
	}
}

func TestLoggingRouteAndMethods(t *testing.T) {
	level := zap.NewAtomicLevel()
	for _, tc := range []struct {
		name    string
		enabled bool
		level   *zap.AtomicLevel
		want    int
	}{
		{name: "enabled", enabled: true, level: &level, want: http.StatusOK},
		{name: "debug disabled", level: &level, want: http.StatusNotFound},
		{name: "no level controller", enabled: true, want: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(Options{EnableDebug: tc.enabled, LogLevel: tc.level})
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				response := loggingRequest(h, method, "/debug/logging", `{"level":"info"}`)
				if response.Code != tc.want {
					t.Fatalf("%s status=%d, want %d", method, response.Code, tc.want)
				}
			}
			index := loggingRequest(h, http.MethodGet, "/", "")
			if advertised := strings.Contains(
				index.Body.String(),
				"/debug/logging",
			); advertised != (tc.want == http.StatusOK) {
				t.Fatalf("index advertises logging=%t, want %t", advertised, tc.want == http.StatusOK)
			}
		})
	}

	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		response := loggingRequest(h, method, "/debug/logging", `{"level":"error"}`)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, PUT" {
			t.Fatalf("%s response=%d, Allow=%q", method, response.Code, response.Header().Get("Allow"))
		}
	}
	for _, path := range []string{"/debug/logging/default", "/debug/logging/"} {
		response := loggingRequest(h, http.MethodPut, path, `{"level":"error"}`)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d, want 404", path, response.Code)
		}
	}
	if level.Level() != zapcore.InfoLevel {
		t.Fatalf("rejected request changed level to %v", level.Level())
	}
}

func TestLoggingConcurrentReadsAndUpdates(t *testing.T) {
	level := zap.NewAtomicLevel()
	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 50 {
				for _, method := range []string{http.MethodPut, http.MethodGet} {
					response := loggingRequest(h, method, "/debug/logging", `{"level":"4"}`)
					if response.Code != http.StatusOK {
						t.Errorf("concurrent %s status=%d", method, response.Code)
					}
				}
			}
		})
	}
	workers.Wait()
}

func loggingRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func assertLoggingResponse(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected response headers: %v", response.Header())
	}
	var result loggingConfig
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Level != want {
		t.Fatalf("level=%q, want %q", result.Level, want)
	}
}
