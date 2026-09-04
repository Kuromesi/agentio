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

package artifacts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStoreRejectsEscapingWriterPath(t *testing.T) {
	store, err := New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Writer("..", "outside"); err == nil {
		t.Fatal("Writer accepted a path escaping the run root")
	}
	if _, err := store.Writer(filepath.Join(string(filepath.Separator), "outside")); err == nil {
		t.Fatal("Writer accepted an absolute path")
	}
}

func TestStoreWriteJSONIsReadableAndAtomic(t *testing.T) {
	store, err := New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"run": "run-1", "success": true}
	if err := store.WriteJSON("environment.json", want); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path("environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", data, err)
	}
	if got["run"] != "run-1" || got["success"] != true {
		t.Fatalf("JSON = %#v", got)
	}
	matches, err := filepath.Glob(store.Path(".environment.json.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestStoreAppendIsSafeForConcurrentJSONLines(t *testing.T) {
	store, err := New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.Append("commands.jsonl", []byte("{\"ok\":true}\n")); err != nil {
				t.Errorf("Append: %v", err)
			}
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(store.Path("commands.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != writers {
		t.Fatalf("line count = %d, want %d; data = %q", got, writers, data)
	}
}
