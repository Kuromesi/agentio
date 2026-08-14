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

	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/filters/mcpacl"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
)

// These tests are the compiler-independent contract between SecurityProfile
// action JSON tags and the filters' policy-neutral payload parsers.
func TestBlockActionPayloadCompatibility(t *testing.T) {
	body := "denied"
	for _, tc := range []struct {
		name   string
		action *v1alpha1.BlockAction
		want   block.Config
	}{
		{"status and body", &v1alpha1.BlockAction{StatusCode: 418, Body: &body},
			block.Config{Status: 418, Body: "denied", HasBody: true}},
		{"status only", &v1alpha1.BlockAction{StatusCode: 403}, block.Config{Status: 403}},
		{"configured empty body", &v1alpha1.BlockAction{StatusCode: 403, Body: ptr.To("")},
			block.Config{Status: 403, HasBody: true}},
		{"undefaulted status", &v1alpha1.BlockAction{}, block.Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := projectAction(t, block.FilterName, block.Definition(), tc.action).(block.Config)
			if got != tc.want {
				t.Errorf("projected config = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMCPToolPolicyPayloadCompatibility(t *testing.T) {
	action := &v1alpha1.MCPToolPolicySpec{
		DefaultAction:            "allow",
		UnsupportedVersionAction: "passthrough",
		DenyResponse:             &v1alpha1.MCPDenyResponse{StatusCode: 401, Body: "no"},
		Rules: []v1alpha1.MCPToolPolicyRule{
			{Method: "tools/call", ToolNames: []string{"a", "b"}, Action: "allow"},
			{Method: "tools/list", Action: "deny"},
		},
	}
	want := mcpacl.Config{
		DefaultAction:            "allow",
		UnsupportedVersionAction: "passthrough",
		DenyStatus:               401,
		DenyBody:                 "no",
		Rules: []mcpacl.RuleEntry{
			{Method: "tools/call", ToolNames: []string{"a", "b"}, Action: "allow"},
			{Method: "tools/list", Action: "deny"},
		},
	}
	got := projectAction(t, mcpacl.FilterName, mcpacl.Definition(), action).(mcpacl.Config)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("projected config = %+v, want %+v", got, want)
	}
}

func TestTokenTransformationPayloadCompatibility(t *testing.T) {
	action := &v1alpha1.TokenTransformationAction{
		CredentialRef: v1alpha1.CredentialRef{
			Secret: &v1alpha1.SecretCredentialRef{Name: "credential", Namespace: "external"},
		},
		ApiKey: &v1alpha1.ApiKeyConfig{
			TargetHeader:  "Authorization",
			ValueTemplate: "Bearer {{ .Token }}",
		},
	}
	got := projectAction(t, tokentransform.FilterName,
		tokentransform.NewDefinition(tokentransform.Deps{}), action).(tokentransform.Config)
	if got.Type != tokentransform.TypeAPIKey || !got.FailBlock {
		t.Errorf("projected type/failure policy = %q/%v, want ApiKey/fail-closed", got.Type, got.FailBlock)
	}
	if got.Source.Kind != tokentransform.SourceKindSecret || got.Source.Name != "credential" || got.Source.Namespace != "external" {
		t.Errorf("projected source = %+v, want external/credential Secret", got.Source)
	}
	apiKey, ok := got.SignerCfg.(tokentransform.ApiKeyConfig)
	if !ok || apiKey.TargetHeader != "authorization" || apiKey.Template == nil {
		t.Errorf("projected signer config = %+v, want compiled authorization ApiKey", got.SignerCfg)
	}
}

func projectAction(t *testing.T, name string, definition filter.Definition, action any) any {
	t.Helper()
	raw, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal %s action: %v", name, err)
	}
	regs, err := filter.Build(definition)
	if err != nil {
		t.Fatalf("build %s definition: %v", name, err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{name: raw})
	if errs[0] != nil {
		t.Fatalf("project %s action: %v", name, errs[0])
	}
	return cfgs[0]
}
