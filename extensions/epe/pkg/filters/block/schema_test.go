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

// Importing v1alpha1 here is legal because this is a test file, and it is
// the whole point: the CRD type is the round-trip oracle that guards the
// json-tag contract between the policy API and this filter's payload
// schema. Production code in this package stays CRD-free.
package block

import (
	"encoding/json"
	"testing"

	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// The CRD action and this filter's payload schema are coupled only by json
// tag names, which the compiler does not check. This test
// is that check: marshal the real v1alpha1 action exactly as payloadsFor
// does, parse it with the real parse, and assert the Config. If either
// side renames a tag, this fails.
func TestRoundTripFromCRDAction(t *testing.T) {
	body := "denied"
	for _, tc := range []struct {
		name   string
		action *v1alpha1.BlockAction
		want   Config
	}{
		{"status and body", &v1alpha1.BlockAction{StatusCode: 418, Body: &body},
			Config{Status: 418, Body: "denied", HasBody: true}},
		{"status only", &v1alpha1.BlockAction{StatusCode: 403},
			Config{Status: 403}},
		{"configured empty body stays a body", &v1alpha1.BlockAction{StatusCode: 403, Body: ptr.To("")},
			Config{Status: 403, Body: "", HasBody: true}},
		{"undefaulted status stays zero for the filter to default", &v1alpha1.BlockAction{},
			Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.action)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got, err := parse(raw)
			if err != nil {
				t.Fatalf("parse(%s): %v", raw, err)
			}
			if got != tc.want {
				t.Errorf("parse(%s) = %+v, want %+v", raw, got, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	if _, err := parse([]byte(`{"statusCode":"nope"}`)); err == nil {
		t.Fatal("parse accepted a non-numeric statusCode")
	}
}
