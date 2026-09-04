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

package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestDynamicLevelChangesExistingHandler(t *testing.T) {
	previous := OutputLevel()
	t.Cleanup(func() { SetOutputLevel(previous) })

	if err := SetOutputLevelName("info"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: DynamicLevel()}))
	logger.Debug("hidden before update")
	if output.Len() != 0 {
		t.Fatalf("info handler emitted debug log: %s", output.String())
	}

	if err := SetOutputLevelName("debug"); err != nil {
		t.Fatal(err)
	}
	logger.Debug("visible after update")
	if !strings.Contains(output.String(), "visible after update") {
		t.Fatalf("existing handler did not observe dynamic level: %s", output.String())
	}

	if err := SetOutputLevelName("none"); err != nil {
		t.Fatal(err)
	}
	logger.Error("hidden after disabling output")
	if strings.Contains(output.String(), "hidden after disabling output") {
		t.Fatalf("none level emitted an error log: %s", output.String())
	}
}

func TestSetOutputLevelNameRejectsInvalidLevel(t *testing.T) {
	previous := OutputLevel()
	t.Cleanup(func() { SetOutputLevel(previous) })
	SetOutputLevel(slog.LevelWarn)

	if err := SetOutputLevelName("verbose"); err == nil {
		t.Fatal("invalid dynamic log level was accepted")
	}
	if got := OutputLevelName(); got != "warn" {
		t.Fatalf("invalid update changed output level to %q", got)
	}
}

func TestComponentLevelsAreIndependent(t *testing.T) {
	previousLogger := slog.Default()
	previousDefault := OutputLevel()
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		ConfigureOutputLevel(previousDefault)
	})
	ConfigureOutputLevel(slog.LevelInfo)

	var output bytes.Buffer
	slog.SetDefault(slog.New(NewDynamicHandler(slog.NewTextHandler(&output,
		&slog.HandlerOptions{Level: slog.LevelDebug}))))
	alpha := New("component-test-alpha")
	beta := New("component-test-beta")
	if err := SetScopeOutputLevelName("component-test-alpha", "debug"); err != nil {
		t.Fatal(err)
	}

	alpha.Debug("alpha visible")
	beta.Debug("beta hidden")
	beta.Info("beta visible")
	got := output.String()
	for _, want := range []string{"alpha visible", "beta visible"} {
		if !strings.Contains(got, want) {
			t.Fatalf("component log output %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "beta hidden") {
		t.Fatalf("beta inherited alpha's debug level: %s", got)
	}
	if level, found := ScopeOutputLevelName("component-test-beta"); !found || level != "info" {
		t.Fatalf("beta level = %q, found=%t, want info", level, found)
	}
}

func TestLoggerUsesCurrentDefaultHandler(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var firstOutput bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&firstOutput, nil)))
	logger := New("inject").With("pod", "demo/example")
	logger.Info("first")

	var secondOutput bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&secondOutput, nil)))
	logger.Info("second")

	if strings.Contains(firstOutput.String(), "second") {
		t.Fatalf("module logger retained the replaced default handler:\n%s", firstOutput.String())
	}
	entry := decodeLogEntry(t, secondOutput.Bytes())
	if entry["msg"] != "second" || entry["component"] != "inject" || entry["pod"] != "demo/example" {
		t.Fatalf("second log entry = %#v, want current handler with module attributes", entry)
	}
}

func TestLoggerReportsOriginalCaller(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{AddSource: true})))
	New("test").Info("caller")

	entry := decodeLogEntry(t, output.Bytes())
	source, ok := entry["source"].(map[string]any)
	if !ok {
		t.Fatalf("source = %#v, want structured source", entry["source"])
	}
	file, _ := source["file"].(string)
	if !strings.HasSuffix(file, "pkg/log/log_test.go") {
		t.Fatalf("source file = %q, want original caller", file)
	}
}

func TestLoggerEnabledUsesCurrentDefaultLevel(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	logger := New("test")
	slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info unexpectedly enabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("error unexpectedly disabled at warn level")
	}
}

func decodeLogEntry(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("decode JSON log: %v\n%s", err, data)
	}
	return entry
}
