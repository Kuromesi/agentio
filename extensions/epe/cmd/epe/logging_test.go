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
	"log/slog"
	"strings"
	"testing"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

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
	t.Cleanup(func() { slog.SetDefault(previousSlog) })
	// The controller-runtime root logger cannot be restored for the same
	// one-shot reason, so it is left pointing at this buffer. Nothing else in
	// this package logs after the test binary finishes.

	var out bytes.Buffer
	opts := ctrlzap.Options{Development: false, DestWriter: &out}
	initLogging(&opts)

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
}
