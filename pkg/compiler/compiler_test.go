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
	"encoding/json"
	"strings"
	"testing"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
)

func TestNewRequiresKRTStop(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	inputs := validCompilerInputs(stop)
	_, err := New(inputs, krt.NewOptionsBuilder(nil, "", nil))
	if err == nil || !strings.Contains(err.Error(), "KRT stop channel") {
		t.Fatalf("New() error = %v, want KRT stop channel error", err)
	}
}

func TestNewPreservesKRTCollectionNames(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	debugger := new(krt.DebugHandler)
	compiler, err := New(validCompilerInputs(stop), krt.NewOptionsBuilder(stop, "", debugger))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	debugDump, err := json.Marshal(debugger)
	if err != nil {
		t.Fatalf("marshal KRT debug collections: %v", err)
	}
	var collections []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(debugDump, &collections); err != nil {
		t.Fatalf("unmarshal KRT debug collections: %v", err)
	}
	names := sets.NewWithLength[string](len(collections))
	for _, collection := range collections {
		names.Insert(collection.Name)
	}
	for _, want := range []string{"configuration", "traffic-policies"} {
		if !names.Contains(want) {
			t.Fatalf("derived KRT collection %q not found in %v", want, names)
		}
	}
	if got := internalCollectionName(t, compiler.graph.resources); got != "resources" {
		t.Fatalf("resources collection name = %q, want %q", got, "resources")
	}
}
