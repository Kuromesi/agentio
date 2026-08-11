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
package bypass

import "testing"

// bypass has no payload fields, so the round-trip that matters is that the
// document payloadsFor emits for `bypass: true` parses to the zero Config.
func TestParseEmptyDocument(t *testing.T) {
	got, err := parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != (Config{}) {
		t.Errorf("parse = %+v, want zero Config", got)
	}
}
