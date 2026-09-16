// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package scenario

import (
	"encoding/json"
	"testing"
)

func TestDecodeOptions(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"value":2}`, `{"typo":1}`, `{} {}`, `{"value":"bad"}`} {
		var options struct {
			Value int `json:"value"`
		}
		err := Decode(json.RawMessage(raw), &options)
		valid := raw == "" || raw == `{}` || raw == `{"value":2}`
		if (err == nil) != valid {
			t.Fatalf("Decode(%q): %v", raw, err)
		}
		if raw == `{"value":2}` && options.Value != 2 {
			t.Fatalf("decoded value = %d, want 2", options.Value)
		}
	}
}
