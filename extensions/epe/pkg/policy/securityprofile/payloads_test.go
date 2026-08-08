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
package securityprofile

import (
	"encoding/json"
	"reflect"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/filters/bypass"
	"istio.io/istio/extensions/epe/pkg/filters/mcpacl"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
)

// registeredNames spells out the registration set wiring.BuildFilters
// produces as a name list: importing wiring here would be an import
// cycle, but every payload key must stay a subset of that set, or
// filter.Project would route a document no filter can parse.
var registeredNames = map[string]bool{
	bypass.FilterName:         true,
	mcpacl.FilterName:         true,
	block.FilterName:          true,
	tokentransform.FilterName: true,
}

func payloadsOrFail(t *testing.T, rule *Rule) map[string]json.RawMessage {
	t.Helper()
	m, err := payloadsFor(rule)
	if err != nil {
		t.Fatalf("payloadsFor: %v", err)
	}
	for name := range m {
		if !registeredNames[name] {
			t.Errorf("payload key %q is not a registered filter name", name)
		}
	}
	return m
}

// The deprecated credentialRef spelling must not survive into the payload:
// the tokentransform filter's schema accepts only the typed union, so a
// document still carrying kind/name/namespace would fail to parse (or
// worse, parse to no credential source at all).
func TestPayloadsForNormalizesDeprecatedCredentialRef(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{
				CredentialRef: v1alpha1.CredentialRef{
					Kind:      v1alpha1.CredentialRefKindSecret,
					Name:      "legacy",
					Namespace: "tenant-a",
				},
			},
		},
	})
	var doc struct {
		CredentialRef struct {
			Secret *struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"secret"`
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"credentialRef"`
		Disabled *bool `json:"disabled"`
	}
	if err := json.Unmarshal(m[tokentransform.FilterName], &doc); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if doc.CredentialRef.Secret == nil {
		t.Fatalf("payload = %s, want a typed secret ref", m[tokentransform.FilterName])
	}
	if doc.CredentialRef.Secret.Name != "legacy" || doc.CredentialRef.Secret.Namespace != "tenant-a" {
		t.Errorf("secret ref = %+v, want legacy/tenant-a", *doc.CredentialRef.Secret)
	}
	if doc.CredentialRef.Kind != "" || doc.CredentialRef.Name != "" {
		t.Errorf("payload = %s, want the deprecated fields gone", m[tokentransform.FilterName])
	}
	// disabled is absorbed by the key's presence, so it must never appear.
	if doc.Disabled != nil {
		t.Errorf("payload = %s, want no disabled field", m[tokentransform.FilterName])
	}
}

// A credentialRef we cannot normalize is a rule we cannot enforce: the
// error must reach the binder's fail-closed path rather than yielding a
// payload-free (and therefore silently unenforced) rule.
func TestPayloadsForRejectsMalformedCredentialRef(t *testing.T) {
	_, err := payloadsFor(&Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{
				CredentialRef: v1alpha1.CredentialRef{Kind: "Unknown", Name: "ref"},
			},
		},
	})
	if err == nil {
		t.Fatal("payloadsFor accepted an unsupported credentialRef kind")
	}
}

func TestPayloadsForRuleWithoutActions(t *testing.T) {
	m := payloadsOrFail(t, &Rule{Name: "r"})
	if len(m) != 0 {
		t.Errorf("payloads = %v, want an empty map", m)
	}
}

// Each action yields exactly its own key: a rule mounting one filter must
// not produce payloads for its siblings.
func TestPayloadsForEachActionYieldsItsOwnKey(t *testing.T) {
	token := &v1alpha1.TokenTransformationAction{
		CredentialRef: v1alpha1.CredentialRef{Kind: v1alpha1.CredentialRefKindSecret, Name: "s"},
	}
	for _, tc := range []struct {
		name    string
		actions v1alpha1.SecurityRuleActions
		wantKey string
	}{
		{"block", v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}}, block.FilterName},
		{"bypass", v1alpha1.SecurityRuleActions{Bypass: true}, bypass.FilterName},
		{"mcpToolPolicy", v1alpha1.SecurityRuleActions{MCPToolPolicy: &v1alpha1.MCPToolPolicySpec{DefaultAction: "deny"}}, mcpacl.FilterName},
		{"tokenTransformation", v1alpha1.SecurityRuleActions{TokenTransformation: token}, tokentransform.FilterName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := payloadsOrFail(t, &Rule{Name: "r", Actions: tc.actions})
			if !reflect.DeepEqual([]string(keys(m)), []string{tc.wantKey}) {
				t.Errorf("keys = %v, want exactly [%s]", keys(m), tc.wantKey)
			}
		})
	}
}

func TestPayloadsForBypassEmitsEmptyDocument(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name:    "r",
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	})
	if got := string(m[bypass.FilterName]); got != `{}` {
		t.Errorf("bypass payload = %s, want {}", got)
	}
}

// Disabled is expressed by omitting the key, so a disabled action mounts
// nothing.
func TestPayloadsForDisabledTokenTransformationYieldsNoKey(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{Disabled: true},
		},
	})
	if len(m) != 0 {
		t.Errorf("payloads = %v, want no key for a disabled action", m)
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
