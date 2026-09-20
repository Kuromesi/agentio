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

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/openkruise/agentio/extensions/epe/pkg/admin"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	agentlog "github.com/openkruise/agentio/pkg/log"
)

// TestInitLoggingBridgesBothStacksOntoZap covers the seam between the two
// logging stacks in this process. Shared agentio packages linked into the EPE
// binary log through pkg/log, which resolves slog.Default() per record, while
// EPE itself logs through controller-runtime's zap. Without the bridge the
// pkg/log records reach Go's built-in handler and print as text inside the JSON
// stream, ignoring the level flags.
//
// Everything is asserted from a single initLogging call because
// ctrllog.SetLogger is one-shot: controller-runtime fulfils the root
// delegating sink once and clears its promise, so a second SetLogger is a
// silent no-op. Subtests share one buffer and reset it between cases.
func TestInitLoggingBridgesBothStacksOntoZap(t *testing.T) {
	previousSlog := slog.Default()
	previousFlags := flag.CommandLine
	t.Cleanup(func() {
		klog.ClearLogger()
		slog.SetDefault(previousSlog)
		flag.CommandLine = previousFlags
	})
	// The controller-runtime root logger cannot be restored for the same
	// one-shot reason, so it is left pointing at this buffer. Nothing else in
	// this package logs after the test binary finishes.

	var out bytes.Buffer
	opts := ctrlzap.Options{Development: false, DestWriter: &out}
	flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	opts.BindFlags(flag.CommandLine)
	// Starting at info installs controller-runtime's production sampler. Runtime
	// changes must still admit EPE's custom V(4)/V(5) levels through that core.
	if err := flag.CommandLine.Parse([]string{"--zap-log-level=info"}); err != nil {
		t.Fatal(err)
	}
	level := initLogging(&opts)

	records := func(t *testing.T) []map[string]any {
		t.Helper()

		var parsed []map[string]any
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("log line is not JSON, so it bypassed the zap encoder: %q (%v)", line, err)
			}
			parsed = append(parsed, record)
		}
		return parsed
	}

	t.Run("shared package logs reach the zap encoder", func(t *testing.T) {
		out.Reset()
		agentlog.New("krt").Info("collection synced", "collection", "workloads")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected exactly one record, got %d: %v", len(got), got)
		}
		record := got[0]
		for key, want := range map[string]any{
			"msg":        "collection synced",
			"component":  "krt",
			"collection": "workloads",
			"level":      "info",
		} {
			if record[key] != want {
				t.Errorf("%s = %v, want %v", key, record[key], want)
			}
		}
		// pkg/log records the caller PC and zapslog turns it into a zap caller,
		// so the line still names its origin rather than the bridge.
		if caller, _ := record["caller"].(string); !strings.Contains(caller, "logging_test.go") {
			t.Errorf("caller = %v, want it to name logging_test.go", record["caller"])
		}
	})

	t.Run("controller-runtime logs stay on the same stream", func(t *testing.T) {
		out.Reset()
		ctrllog.Log.WithName("ext-proc").Info("handling request headers", "requestID", "abc")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected exactly one record, got %d: %v", len(got), got)
		}
		if got[0]["logger"] != "ext-proc" {
			t.Errorf("logger = %v, want %q", got[0]["logger"], "ext-proc")
		}
		if got[0]["requestID"] != "abc" {
			t.Errorf("requestID = %v, want %q", got[0]["requestID"], "abc")
		}
	})

	t.Run("debug stays gated in this process", func(t *testing.T) {
		out.Reset()
		logger := agentlog.New("krt")
		if !logger.Enabled(t.Context(), slog.LevelInfo) {
			t.Error("info records must reach the handler")
		}
		// pkg/log filters by its own scope level before any handler sees the
		// record, and nothing here raises it, so debug stays off however
		// verbose -v is. That is deliberate: pkg/krt emits debug lines per
		// event on the recompute path, and -v defaults to 2, which zap admits.
		if logger.Enabled(t.Context(), slog.LevelDebug) {
			t.Error("debug records must stay gated in the EPE process")
		}

		logger.Debug("handled event", "resource", "key")
		logger.Info("watch started")

		got := records(t)
		if len(got) != 1 {
			t.Fatalf("expected only the info record, got %d: %v", len(got), got)
		}
		if got[0]["msg"] != "watch started" {
			t.Errorf("msg = %v, want %q", got[0]["msg"], "watch started")
		}
	})

	t.Run("admin updates existing loggers across the bridges", func(t *testing.T) {
		server := httptest.NewServer(admin.NewHandler(admin.Options{EnableDebug: true, LogLevel: &level}))
		defer server.Close()
		existing := ctrllog.Log.WithName("ext-proc").WithValues("requestID", "already-created")
		existingSlog := slog.Default().With("source", "already-created")
		shared := agentlog.New("krt")
		update := func(name string) {
			t.Helper()
			request, err := http.NewRequest(http.MethodPut, server.URL+"/debug/logging/default",
				strings.NewReader(`{"output_level":"`+name+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("PUT output_level %q: status=%d, want 202", name, response.StatusCode)
			}
		}

		out.Reset()
		existing.V(logging.DEBUG).Info("hidden before update")
		update("debug")
		existing.V(logging.DEBUG).Info("debug enabled")
		existing.V(logging.TRACE).Info("trace still hidden")
		got := records(t)
		if len(got) != 1 || got[0]["msg"] != "debug enabled" || got[0]["requestID"] != "already-created" {
			t.Fatalf("debug update records = %v", got)
		}

		out.Reset()
		update("5")
		existing.V(logging.TRACE).Info("trace enabled")
		if got := records(t); len(got) != 1 || got[0]["msg"] != "trace enabled" {
			t.Fatalf("trace update records = %v", got)
		}

		out.Reset()
		update("error")
		existing.Info("hidden logr")
		existingSlog.Info("hidden slog")
		klog.InfoS("hidden klog")
		shared.Info("hidden shared package")
		existing.Error(io.EOF, "visible error")
		got = records(t)
		if len(got) != 1 || got[0]["msg"] != "visible error" {
			t.Fatalf("error update records = %v", got)
		}
		if _, found := got[0]["stacktrace"]; found {
			t.Fatal("changing level enabled error stacktraces")
		}

		out.Reset()
		update("info")
		existing.V(logging.DEFAULT).Info("restored EPE default")
		existing.V(logging.VERBOSE).Info("verbose hidden after info reset")
		existing.V(logging.DEBUG).Info("debug hidden after info reset")
		existing.Info("restored logr")
		existingSlog.Info("restored slog")
		klog.InfoS("restored klog")
		shared.Info("restored shared package")
		if got := records(t); len(got) != 5 {
			t.Fatalf("restored logger records = %v", got)
		}

		out.Reset()
		update("none")
		existing.Error(io.EOF, "hidden logr error")
		existingSlog.Error("hidden slog error")
		klog.ErrorS(io.EOF, "hidden klog error")
		shared.Error("hidden shared error")
		if got := records(t); len(got) != 0 {
			t.Fatalf("none should suppress every record: %v", got)
		}

		out.Reset()
		update("1")
		existingSlog.Debug("slog debug enabled")
		existing.V(logging.DEBUG).Info("EPE V4 still hidden")
		if got := records(t); len(got) != 1 || got[0]["msg"] != "slog debug enabled" {
			t.Fatalf("verbosity 1 records = %v", got)
		}
	})
}

func TestNewLogLevelHonorsStartupFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want zapcore.Level
	}{
		{name: "default", want: -2},
		{name: "verbosity", args: []string{"-v=4"}, want: -4},
		{name: "info overrides verbosity", args: []string{"-v=5", "--zap-log-level=info"}, want: zapcore.InfoLevel},
		{name: "numeric zap level", args: []string{"--zap-log-level=3", "-v=5"}, want: -3},
		{name: "named zap level", args: []string{"--zap-log-level=debug"}, want: zapcore.DebugLevel},
		{name: "development preserves verbosity", args: []string{"--zap-devel"}, want: -2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousFlags, previousVerbosity := flag.CommandLine, *logVerbosity
			t.Cleanup(func() {
				flag.CommandLine = previousFlags
				*logVerbosity = previousVerbosity
			})
			flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			flag.IntVar(logVerbosity, "v", 2, "log verbosity")
			opts := ctrlzap.Options{}
			opts.BindFlags(flag.CommandLine)
			if err := flag.CommandLine.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if got := newLogLevel(&opts).Level(); got != tc.want {
				t.Fatalf("startup level = %v, want %v", got, tc.want)
			}
		})
	}
}
