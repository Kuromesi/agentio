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
package mcpacl

import (
	"encoding/json"
	"reflect"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// The CRD action and this filter's payload schema are coupled only by json
// tag names, which the compiler does not check. This test
// is that check: marshal the real v1alpha1 action exactly as payloadsFor
// does, parse it with the real parse, and assert the Config. If either
// side renames a tag, this fails.
func TestRoundTripFromCRDAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action *v1alpha1.MCPToolPolicySpec
		want   Config
	}{
		{
			"full policy",
			&v1alpha1.MCPToolPolicySpec{
				DefaultAction:            "allow",
				UnsupportedVersionAction: "passthrough",
				DenyResponse:             &v1alpha1.MCPDenyResponse{StatusCode: 401, Body: "no"},
				Rules: []v1alpha1.MCPToolPolicyRule{
					{Method: "tools/call", ToolNames: []string{"a", "b"}, Action: "allow"},
					{Method: "tools/list", Action: "deny"},
				},
			},
			Config{
				DefaultAction:            "allow",
				UnsupportedVersionAction: "passthrough",
				DenyStatus:               401,
				DenyBody:                 "no",
				Rules: []RuleEntry{
					{Method: "tools/call", ToolNames: []string{"a", "b"}, Action: "allow"},
					{Method: "tools/list", Action: "deny"},
				},
			},
		},
		// Un-defaulted values must reach the filter verbatim rather than
		// being invented here; evaluate is what fails them closed.
		{"empty policy stays zero", &v1alpha1.MCPToolPolicySpec{}, Config{}},
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
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parse(%s) = %+v, want %+v", raw, got, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	if _, err := parse([]byte(`{"defaultAction":42}`)); err == nil {
		t.Fatal("parse accepted a non-string defaultAction")
	}
}
