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

package e2e

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/artifacts"
)

func TestFullDiagnosticsAreBoundedAndKeepOriginalFailure(t *testing.T) {
	store, err := artifacts.New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSuite(SuiteSpec{Name: "unit"}, DefaultConfig())
	s.config.Diagnostics.FullOnFailure = true
	s.config.Diagnostics.MaxFullDumps = 1
	collector := &failingCollector{}
	s.RegisterCollector(collector)
	env := &Environment{RunID: "run-1", Artifacts: store}

	firstErr := s.collectFailure(context.Background(), env, "tests/unit", errors.New("original test failure"))
	if firstErr == nil || !strings.Contains(firstErr.Error(), "collector broken") {
		t.Fatalf("first collection error = %v", firstErr)
	}
	if err := s.collectFailure(context.Background(), env, "tests/unit-second", errors.New("second failure")); err != nil {
		t.Fatalf("bounded collection returned error: %v", err)
	}
	if collector.calls != 1 {
		t.Fatalf("collector calls = %d, want 1", collector.calls)
	}
	data, err := os.ReadFile(store.Path("tests/unit/failure.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "original test failure") || strings.Contains(string(data), "collector broken") {
		t.Fatalf("failure artifact = %q", data)
	}
}

type failingCollector struct{ calls int }

func (*failingCollector) Name() string { return "broken" }

func (f *failingCollector) Collect(context.Context, *Environment, artifacts.Writer) error {
	f.calls++
	return errors.New("collector broken")
}
