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
package inputs

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/cel-go/cel"
)

// TestBuildSlotsAreJSONNative walks every slot the activation exposes and
// requires it to survive JSON marshalling. This is the shape of the bug that
// actually shipped: a map-valued credentialProvider parameter failed with
// "result is not JSON-compatible" because cel-go converts a map result to
// map[any]any. Adding a slot whose container eval.ownedNative does not
// normalise fails here.
//
// It lives in package inputs and reads buildBag() directly so that the sweep is
// driven by the bag's real contents rather than by a hand-maintained list.
func TestBuildSlotsAreJSONNative(t *testing.T) {
	s := NewScope(
		Request{
			Host: "h", Port: 443, Path: "/", Scheme: "https", Method: "GET",
			headers: map[string]string{"x": "1"},
			Query:   map[string][]string{"q": {"v"}},
		},
		Pod{Name: "p", Namespace: "ns", IP: "1.2.3.4", Labels: map[string]string{"l": "1"}},
		Profile{Name: "sp", Namespace: "spns"},
		Rule{Name: "r"},
		map[string]any{"tier": "gold"},
	)
	bag := s.buildBag()
	if len(bag) == 0 {
		t.Fatal("bag is empty")
	}
	for name, slot := range bag {
		t.Run(name, func(t *testing.T) {
			if slot == nil {
				return // `inputs` may legitimately be nil
			}
			if _, err := json.Marshal(slot); err != nil {
				t.Fatalf("slot %q (%T) is not JSON-marshalable: %v", name, slot, err)
			}
		})
	}
	// The bag must also be acceptable to cel-go.
	if _, err := cel.NewActivation(bag); err != nil {
		t.Fatalf("cel.NewActivation: %v", err)
	}
}

// TestBuildBagCarriesNoSecretKey is the bag-level half of the secrets
// guarantee. The env-level check in TestScopeNeverExposesSecrets asserts that
// no banned name is a *declared* CEL variable; it says nothing about what the
// bag holds, so a future slot literally named "token" would pass it. This walks
// the projected bag at every nesting depth instead, and is driven by buildBag's
// real contents rather than by a list of slots someone has to maintain.
func TestBuildBagCarriesNoSecretKey(t *testing.T) {
	banned := map[string]bool{
		"sandboxtoken": true, "requestbody": true, "token": true,
		"body": true, "secret": true, "credential": true,
	}
	s := NewScope(
		Request{
			Host: "h", Port: 443, Path: "/", Scheme: "https", Method: "GET",
			headers: map[string]string{"x-tenant": "a"},
			Query:   map[string][]string{"q": {"v"}},
		},
		Pod{Name: "p", Namespace: "ns", IP: "1.2.3.4", Labels: map[string]string{"app": "sleep"}},
		Profile{Name: "sp", Namespace: "spns"},
		Rule{Name: "r"},
		map[string]any{"tier": "gold"},
	)

	// The `inputs` slot is caller-supplied profile data, not a projection of
	// request state, so its keys are outside this guarantee: a profile may
	// legitimately declare an input named "token". Everything the projection
	// itself invents is in scope.
	var walk func(t *testing.T, path string, v any)
	walk = func(t *testing.T, path string, v any) {
		rv := reflect.ValueOf(v)
		if !rv.IsValid() || rv.Kind() != reflect.Map {
			return
		}
		for _, k := range rv.MapKeys() {
			key := fmt.Sprint(k.Interface())
			child := path + "." + key
			if banned[strings.ToLower(key)] {
				t.Errorf("bag exposes banned key %q at %s", key, child)
			}
			walk(t, child, rv.MapIndex(k).Interface())
		}
	}
	for name, slot := range s.buildBag() {
		if name == "inputs" {
			continue
		}
		if banned[strings.ToLower(name)] {
			t.Errorf("bag exposes banned top-level slot %q", name)
		}
		walk(t, name, slot)
	}
}

// TestBuildSharesSourceMaps pins that the bag references the caller's maps
// rather than copying them. This is deliberate — the copy it replaces cost
// O(headers) per evaluation — and it is asserted so that a future "defensive"
// copy cannot land silently. A copy would not make an in-place mutation safe;
// it would make it invisible.
func TestBuildSharesSourceMaps(t *testing.T) {
	headers := map[string]string{"x": "1"}
	labels := map[string]string{"l": "1"}
	in := map[string]any{"tier": "gold"}
	s := NewScope(
		Request{Host: "h", headers: headers},
		Pod{Labels: labels}, Profile{}, Rule{}, in,
	)
	bag := s.buildBag()

	if !sameMap(bag["request"].(map[string]any)["headers"], headers) {
		t.Error("request.headers must be the source map, not a copy")
	}
	if !sameMap(bag["pod"].(map[string]any)["labels"], labels) {
		t.Error("pod.labels must be the source map, not a copy")
	}
	if !sameMap(bag["inputs"], in) {
		t.Error("inputs must be the source map, not a copy")
	}
	// queryParams is genuinely built — it flattens map[string][]string to
	// first-value-per-key — so it has no source map to be compared against; its
	// contents are pinned by the I6 arm of TestScopeInvariants.
}

// sameMap reports whether a and b are the same map header. reflect.Value.Pointer
// on a map returns its runtime pointer, which is the documented way to compare
// map identity.
//
// Nil maps are rejected rather than compared: two nil maps both yield pointer 0,
// so without this guard a future caller passing a nil map would satisfy the
// identity check vacuously.
func sameMap(a, b any) bool {
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if !ra.IsValid() || !rb.IsValid() || ra.IsNil() || rb.IsNil() {
		return false
	}
	return ra.Pointer() == rb.Pointer()
}

// TestBuildBagKeySetIsExact pins the base bag's key set exactly, not merely the
// absence of the two audit-only names TestScopeHidesAuditOnlyVariables checks.
// That test enumerates `result` and `response`, so a contributor adding a
// phase-varying slot under any other name — responseHeaders, requestBody —
// passes it while breaking the memoisation contract. This fails instead.
func TestBuildBagKeySetIsExact(t *testing.T) {
	want := map[string]bool{
		"request": true, "pod": true, "profile": true, "rule": true, "inputs": true,
	}
	const rule = "the memoised base bag holds only variables fixed when the unit is bound, " +
		"because Activation caches it for the Scope's lifetime. A variable whose value can " +
		"change within that lifetime (a result, a response, a response header, a buffered " +
		"body) would freeze at the first evaluation. Such a variable belongs in the " +
		"hierarchical child built by audit.Scope.Activation (audit/scope.go), not in buildBag"

	bag := NewScope(
		Request{Host: "h", Port: 443, headers: map[string]string{"x": "1"}},
		Pod{Name: "p", Labels: map[string]string{"l": "1"}},
		Profile{Name: "sp"}, Rule{Name: "r"},
		map[string]any{"tier": "gold"},
	).buildBag()

	for name := range bag {
		if !want[name] {
			t.Errorf("buildBag exposes unexpected slot %q.\n%s", name, rule)
		}
	}
	for name := range want {
		if _, ok := bag[name]; !ok {
			t.Errorf("buildBag no longer exposes required slot %q; if it was moved to a "+
				"hierarchical child, this test and the doc on buildBag must move with it", name)
		}
	}
}

// TestBuildNonNilMaps pins that headers, queryParams and labels are never nil,
// so the bag's shape does not depend on what the request carried.
func TestBuildNonNilMaps(t *testing.T) {
	bag := NewScope(Request{}, Pod{}, Profile{}, Rule{}, nil).buildBag()
	req := bag["request"].(map[string]any)
	if req["headers"].(map[string]string) == nil {
		t.Error("request.headers must not be nil")
	}
	if req["queryParams"].(map[string]string) == nil {
		t.Error("request.queryParams must not be nil")
	}
	if bag["pod"].(map[string]any)["labels"].(map[string]string) == nil {
		t.Error("pod.labels must not be nil")
	}
	if _, ok := bag["inputs"]; !ok {
		t.Error("inputs must be present even when nil")
	}
}

// TestActivationMemoises pins that the bag is built once per Scope, including
// when the first call arrives through audit's by-value copy of the Scope.
func TestActivationMemoises(t *testing.T) {
	s := NewScope(Request{Host: "h"}, Pod{}, Profile{}, Rule{}, nil)
	first := s.Activation()
	if second := s.Activation(); second != first {
		t.Error("Activation must memoise")
	}

	// A by-value copy shares the cache pointer, as audit's buildScope relies on.
	copyOfScope := *s
	if fromCopy := copyOfScope.Activation(); fromCopy != first {
		t.Error("a by-value copy must share the memoised activation")
	}

	// And the copy can legitimately be the first caller.
	fresh := NewScope(Request{Host: "h2"}, Pod{}, Profile{}, Rule{}, nil)
	c := *fresh
	viaCopy := c.Activation()
	if viaCopy != fresh.Activation() {
		t.Error("a first call through the copy must populate the shared cache")
	}
}

// TestActivationConcurrent runs under -race: the Once is what allows a sink
// that defers rendering to its workers (audit/sink.go:20 permits it) to reach
// Activation() off the stream goroutine.
func TestActivationConcurrent(t *testing.T) {
	s := NewScope(
		Request{Host: "h", headers: map[string]string{"x": "1"}},
		Pod{Labels: map[string]string{"l": "1"}}, Profile{}, Rule{}, nil,
	)
	const n = 64
	got := make([]cel.Activation, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); got[i] = s.Activation() }(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("goroutine %d saw a different activation", i)
		}
	}
}

// TestActivationWithoutNewScopePanics documents the deliberate absence of a
// fallback: a zero-value Scope has no data to project, so calling Activation on
// it is a programming error that should report itself immediately.
func TestActivationWithoutNewScopePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Activation on a literal-built Scope must panic")
		}
	}()
	(&Scope{}).Activation()
}
