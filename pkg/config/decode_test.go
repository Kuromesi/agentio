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

package config_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

func TestApplyConfigOverlay(t *testing.T) {
	base, err := config.Apply(`extensionProviders:
- name: base
  credentialProvider: {url: https://base.example}
defaultProviders: {credentialProvider: base}
`, &configv1.EPEConfig{})
	if err != nil {
		t.Fatal(err)
	}
	original := proto.Clone(base)
	for _, tt := range []struct {
		name            string
		raw             string
		provider        string
		defaultProvider string
		invalid         bool
	}{
		{name: "omitted", raw: "{}", provider: "base", defaultProvider: "base"},
		{name: "null document", raw: "null", provider: "base", defaultProvider: "base"},
		{name: "null", raw: "extensionProviders: null\ndefaultProviders: null", provider: "base", defaultProvider: "base"},
		{name: "select default", raw: "defaultProviders: {credentialProvider: default}", provider: "base", defaultProvider: "default"},
		{name: "reset message", raw: "defaultProviders: {}", provider: "base"},
		{name: "clear list", raw: "extensionProviders: []", defaultProvider: "base"},
		{
			name:            "replace list",
			raw:             "extensionProviders: [{name: primary, httpCallout: {url: https://primary.example}}]",
			provider:        "primary",
			defaultProvider: "base",
		},
		{name: "protobuf field name", raw: "extension_providers: []", defaultProvider: "base"},
		{
			name: "conflicting provider types",
			raw: "extensionProviders: [{name: primary, httpCallout: {url: https://example}, " +
				"credentialProvider: {url: https://example}}]",
			invalid: true,
		},
		{name: "duplicate YAML key", raw: "defaultProviders: {}\ndefaultProviders: {}", invalid: true},
		{name: "unknown field", raw: "unknown: true", invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.Apply(tt.raw, base)
			if (err != nil) != tt.invalid {
				t.Fatalf("Apply() error = %v, want invalid=%v", err, tt.invalid)
			}
			if !proto.Equal(base, original) {
				t.Fatal("overlay mutated the base configuration")
			}
			if tt.invalid {
				return
			}
			providers := got.GetExtensionProviders()
			if tt.provider == "" {
				if len(providers) != 0 {
					t.Fatalf("providers = %v, want empty", providers)
				}
			} else if len(providers) != 1 || providers[0].Name != tt.provider {
				t.Fatalf("providers = %v, want only %q", providers, tt.provider)
			}
			if got.GetDefaultProviders().GetCredentialProvider() != tt.defaultProvider {
				t.Fatalf(
					"default provider = %q, want %q",
					got.GetDefaultProviders().GetCredentialProvider(),
					tt.defaultProvider,
				)
			}
		})
	}
}
