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

package compiler

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/model"
)

func TestMain(m *testing.M) {
	// krt logs a line per collection sync at info level. That is useful in a
	// running control plane and pure noise in a test run.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	os.Exit(m.Run())
}

// waitSynced blocks until the compiler's derived collections are populated.
func waitSynced(t testing.TB, compiler *Compiler) {
	t.Helper()
	stop := make(chan struct{})
	timer := time.AfterFunc(30*time.Second, func() { close(stop) })
	defer timer.Stop()
	if !compiler.WaitUntilSynced(stop) {
		t.Fatal("compiler did not sync")
	}
}

// compileSynced waits for the graph and then compiles, failing the test on error.
func compileSynced(t testing.TB, compiler *Compiler) model.ResourceSet {
	t.Helper()
	waitSynced(t, compiler)
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if failures := compiler.Failures(); len(failures) > 0 {
		t.Fatalf("objects failed to compile: %v", failures)
	}
	return snapshot
}
