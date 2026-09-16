// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package scenario

import (
	"encoding/json"
	"testing"
)

func TestRegistryCreatesIndependentInstances(t *testing.T) {
	type options struct {
		Value int `json:"value"`
	}
	r := NewRegistry[*options]()
	f := func(raw json.RawMessage) (*options, error) {
		var o options
		return &o, Decode(raw, &o)
	}
	if err := r.Register("test", f); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("test", f); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if _, err := r.New("missing", nil); err == nil {
		t.Fatal("unknown scenario accepted")
	}
	a, err := r.New("test", json.RawMessage(`{"value":2}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.New("test", json.RawMessage(`{"value":2}`))
	if err != nil {
		t.Fatal(err)
	}
	a.Value++
	if b.Value != 2 {
		t.Fatal("instances share mutable state")
	}
	for _, raw := range []string{`{"typo":1}`, `{} {}`, `{"value":"bad"}`} {
		if _, err := r.New("test", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted invalid config %s", raw)
		}
	}
}
