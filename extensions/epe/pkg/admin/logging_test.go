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
	assertScopeResponse(t, initial, "info", true)

	for _, tc := range []struct {
		input  string
		output string
		level  zapcore.Level
	}{
		{input: "4", output: "debug", level: -4},
		{input: "2", output: "info", level: -2},
		{input: "3", output: "3", level: -3},
		{input: "5", output: "5", level: -5},
		{input: "127", output: "127", level: -127},
		{input: "0", output: "0", level: zapcore.InfoLevel},
		{input: "1", output: "1", level: zapcore.DebugLevel},
		{input: "dpanic", output: "dpanic", level: zapcore.DPanicLevel},
		{input: "panic", output: "panic", level: zapcore.PanicLevel},
		{input: "fatal", output: "fatal", level: zapcore.FatalLevel},
	} {
		t.Run(tc.input, func(t *testing.T) {
			response := loggingRequest(h, http.MethodPut, "/debug/logging", `{"output_level":"`+tc.input+`"}`)
			if response.Code != http.StatusAccepted || response.Body.Len() != 0 {
				t.Fatalf("status=%d, body=%s", response.Code, response.Body.String())
			}
			if got := level.Level(); got != tc.level {
				t.Fatalf("logger level = %v, want %v", got, tc.level)
			}
			get := loggingRequest(h, http.MethodGet, "/debug/logging/default", "")
			assertScopeResponse(t, get, tc.output, false)
			// The agentiod-style representation preserves even custom Zap levels.
			roundTrip := loggingRequest(h, http.MethodPut, "/debug/logging/default", get.Body.String())
			if roundTrip.Code != http.StatusAccepted || level.Level() != tc.level {
				t.Fatalf("round trip: status=%d, level=%v, want %v", roundTrip.Code, level.Level(), tc.level)
			}
		})
	}
}

func TestAgentiodLoggingAPI(t *testing.T) {
	level := zap.NewAtomicLevelAt(-2)
	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	for _, path := range []string{"/debug/logging", "/debug/logging/", "/debug/logging/default"} {
		for _, tc := range []struct {
			input string
			want  string
			level zapcore.Level
		}{
			{input: "debug", want: "debug", level: -4},
			{input: "info", want: "info", level: -2},
			{input: "warn", want: "warn", level: zapcore.WarnLevel},
			{input: "error", want: "error", level: zapcore.ErrorLevel},
			{input: "none", want: "none", level: disabledLoggingLevel},
			{input: " DEBUG ", want: "debug", level: -4},
		} {
			for _, name := range []string{"", "default"} {
				body := `{"name":"` + name + `","output_level":"` + tc.input + `"}`
				response := loggingRequest(h, http.MethodPut, path, body)
				if response.Code != http.StatusAccepted || response.Body.Len() != 0 {
					t.Fatalf("PUT %s %s: status=%d, body=%s", path, body, response.Code, response.Body.String())
				}
				if response.Header().Get("Cache-Control") != "no-store" || level.Level() != tc.level {
					t.Fatalf("PUT %s %s: headers=%v, level=%v", path, body, response.Header(), level.Level())
				}
				get := loggingRequest(h, http.MethodGet, path, "")
				assertScopeResponse(t, get, tc.want, path != "/debug/logging/default")
			}
		}
	}
}

func TestLoggingRejectsInvalidUpdatesWithoutChangingLevel(t *testing.T) {
	level := zap.NewAtomicLevelAt(zapcore.WarnLevel)
	h := NewHandler(Options{EnableDebug: true, LogLevel: &level})
	for _, body := range []string{
		``, `{`, `null`, `[]`, `{}`, `{"name":"default"}`,
		`{"output_level":null}`, `{"output_level":""}`, `{"output_level":4}`,
		`{"output_level":"verbose"}`, `{"output_level":"-1"}`, `{"output_level":"128"}`,
		`{"output_level":"256"}`, `{"output_level":"4.0"}`, `{"output_level":"999999999999999999999999"}`,
		`{"name":"krt","output_level":"debug"}`,
		`{"output_level":"debug","unknown":true}`, `{"output_level":"debug"} {}`,
		`{"output_level":"debug"} trailing`,
		`{"output_level":"` + strings.Repeat("x", maxLoggingBodyBytes) + `"}`,
		`{"output_level":"debug"}` + strings.Repeat(" ", maxLoggingBodyBytes),
		// Only output_level is accepted, including when both fields are supplied.
		`{"level":"debug"}`, `{"level":"4"}`, `{"output_level":"debug","level":"4"}`,
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
			for _, path := range []string{"/debug/logging", "/debug/logging/", "/debug/logging/default"} {
				for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
					response := loggingRequest(h, method, path, `{"output_level":"info"}`)
					want := tc.want
					if method == http.MethodPut && want == http.StatusOK {
						want = http.StatusAccepted
					}
					if response.Code != want {
						t.Fatalf("%s %s status=%d, want %d", method, path, response.Code, want)
					}
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
	previousLevel := level.Level()
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		response := loggingRequest(h, method, "/debug/logging", `{"output_level":"error"}`)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD, PUT" {
			t.Fatalf("%s response=%d, Allow=%q", method, response.Code, response.Header().Get("Allow"))
		}
	}
	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/debug/logging", want: http.StatusOK},
		{path: "/debug/logging/", want: http.StatusOK},
		{path: "/debug/logging/default", want: http.StatusOK},
		{path: "/debug/logging/krt", want: http.StatusBadRequest},
		{path: "/debug/logging/default/", want: http.StatusNotFound},
		{path: "/debug/logging/default/extra", want: http.StatusNotFound},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
			if method == http.MethodPut && tc.want == http.StatusOK {
				continue
			}
			response := loggingRequest(h, method, tc.path, `{"output_level":"error"}`)
			if response.Code != tc.want {
				t.Fatalf("%s %s status=%d, want %d", method, tc.path, response.Code, tc.want)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatalf("HEAD %s has body %s", tc.path, response.Body.String())
			}
		}
	}
	if level.Level() != previousLevel {
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
					response := loggingRequest(h, method, "/debug/logging/default", `{"output_level":"debug"}`)
					want := http.StatusOK
					if method == http.MethodPut {
						want = http.StatusAccepted
					}
					if response.Code != want {
						t.Errorf("concurrent %s status=%d, want %d", method, response.Code, want)
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

func assertScopeResponse(t *testing.T, response *httptest.ResponseRecorder, want string, list bool) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected response headers: %v", response.Header())
	}
	var scopes []loggingInfo
	if list {
		if err := json.Unmarshal(response.Body.Bytes(), &scopes); err != nil {
			t.Fatal(err)
		}
	} else {
		var scope loggingInfo
		if err := json.Unmarshal(response.Body.Bytes(), &scope); err != nil {
			t.Fatal(err)
		}
		scopes = []loggingInfo{scope}
	}
	if len(scopes) != 1 || scopes[0].Name != "default" || scopes[0].OutputLevel != want {
		t.Fatalf("scopes=%+v, want only default with output_level=%q", scopes, want)
	}
}
