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
