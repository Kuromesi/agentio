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
package tokentransform

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/utils/ptr"
)

// parseSpec exercises the JSON boundary using the filter-owned wire type.
// Compatibility with concrete policy APIs is tested in testing/securityprofile.
func parseSpec(t *testing.T, tt *spec) (Config, error) {
	t.Helper()
	raw, err := json.Marshal(tt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return parse(raw)
}

func apiKeyTT() *spec {
	return &spec{
		CredentialRef: credentialRefSpec{
			Secret: &secretRefSpec{Name: "s", Namespace: "ns"},
		},
		ApiKey: &apiKeySpec{TargetHeader: "authorization", ValueTemplate: "Bearer {{ .Token }}"},
	}
}

func TestParseClaimsApiKeyAction(t *testing.T) {
	cfg, err := parseSpec(t, apiKeyTT())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAPIKey {
		t.Errorf("Type = %q, want %q", cfg.Type, TypeAPIKey)
	}
	want := SourceSpec{Kind: SourceKindSecret, Name: "s", Namespace: "ns"}
	if cfg.Source.Kind != want.Kind || cfg.Source.Name != want.Name || cfg.Source.Namespace != want.Namespace {
		t.Errorf("Source = %+v, want %+v", cfg.Source, want)
	}
	ac, ok := cfg.SignerCfg.(ApiKeyConfig)
	if !ok || ac.TargetHeader != "authorization" || ac.Template == nil {
		t.Errorf("SignerCfg = %+v, want a compiled ApiKeyConfig", cfg.SignerCfg)
	}
}

// An empty type is the un-defaulted case; the CRD defaults it to ApiKey and
// so does the filter, so a config that never went through API-server
// defaulting still resolves to a real signer instead of failing.
func TestParseDefaultsEmptyTypeToApiKey(t *testing.T) {
	tt := apiKeyTT()
	tt.Type = ""
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAPIKey {
		t.Errorf("Type = %q, want %q", cfg.Type, TypeAPIKey)
	}
}

func TestParseUnregisteredTypeFailsClosed(t *testing.T) {
	tt := apiKeyTT()
	tt.Type = "NoSuchType"
	_, err := parseSpec(t, tt)
	if err == nil || !strings.Contains(err.Error(), "no signer") {
		t.Fatalf("err = %v, want unregistered-signer error", err)
	}
}

func TestParseAliyunSTSClaimsWhenRegistered(t *testing.T) {
	if !HasSigner(TypeAliyunSTS) {
		t.Skip("AliyunSTS signer not registered in this build")
	}
	tt := apiKeyTT()
	tt.Type = TypeAliyunSTS
	tt.ApiKey = nil
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Type != TypeAliyunSTS || cfg.SignerCfg != nil {
		t.Fatalf("cfg = %+v, want AliyunSTS with no signer cfg", cfg)
	}
}

// Types the build cannot serve fail at parse time even when the signer
// registry is empty.
func TestParseFailsClosedWithEmptySignerRegistry(t *testing.T) {
	restore := swapSigners()
	defer restore()
	_, err := parseSpec(t, apiKeyTT())
	if err == nil || !strings.Contains(err.Error(), "no signer") {
		t.Fatalf("err = %v, want unregistered-signer error", err)
	}
}

func TestParseFailStrategy(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		want     bool
	}{
		{"Block", true},
		{"Allow", false},
		{"Ignore", false},
		// Only the two explicit open values open. An empty value means the
		// payload never went through API-server defaulting, and the CRD
		// defaults this field to Block — so blocking is what the operator
		// asked for. An unrecognized value is likewise resolved fail-closed,
		// matching block's status-0 and mcpacl's empty-defaultAction handling.
		{"", true},
		{"SomethingNobodyRegistered", true},
	} {
		t.Run(string(tc.strategy), func(t *testing.T) {
			tt := apiKeyTT()
			tt.FailStrategy = tc.strategy
			cfg, err := parseSpec(t, tt)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.FailBlock != tc.want {
				t.Errorf("FailBlock = %v, want %v", cfg.FailBlock, tc.want)
			}
		})
	}
}

func TestParseWhenCompiled(t *testing.T) {
	tt := apiKeyTT()
	tt.ApiKey.When = &whenSpec{Header: "X-Guard", Pattern: "^v.*"}
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.When == nil || cfg.When.Header != "X-Guard" || !cfg.When.Re.MatchString("v1") {
		t.Fatalf("When = %+v, want a compiled ^v.* on X-Guard", cfg.When)
	}
}

func TestParseProviderParametersCompiled(t *testing.T) {
	tt := apiKeyTT()
	tt.CredentialRef = credentialRefSpec{
		CredentialProvider: &providerRefSpec{
			Name: "prov",
			Parameters: map[string]valueSourceSpec{
				"static":   {Value: ptr.To("x")},
				"template": {Template: ptr.To("{{ .Pod.Name }}")},
				"cel":      {Cel: ptr.To("pod.name")},
			},
		},
	}
	cfg, err := parseSpec(t, tt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.Kind != SourceKindProvider || cfg.Source.Name != "prov" {
		t.Fatalf("Source = %+v, want the provider ref", cfg.Source)
	}
	p := cfg.Source.Parameters
	if len(p) != 3 || p["static"].Value == nil || p["template"].Template == nil || p["cel"].Cel == nil {
		t.Fatalf("compiled params = %+v, want all three branches compiled", p)
	}
}

func TestParseRejectsAuditOnlyResultInProviderParameter(t *testing.T) {
	tt := apiKeyTT()
	tt.CredentialRef = credentialRefSpec{
		CredentialProvider: &providerRefSpec{
			Name: "prov",
			Parameters: map[string]valueSourceSpec{
				"audit-only": {Cel: ptr.To("result")},
			},
		},
	}
	_, err := parseSpec(t, tt)
	if err == nil || !strings.Contains(err.Error(), "undeclared reference to 'result'") {
		t.Fatalf("parseSpec() error = %v, want undeclared-reference error", err)
	}
}

// Every malformed payload must fail closed at parse time: the binder turns
// these into a denied request, so none of them can degrade into a silently
// unenforced rule.
func TestParseFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		mut  func(*spec)
	}{
		{"nil apiKey while type is ApiKey", "apiKey config is nil", func(tt *spec) {
			tt.ApiKey = nil
		}},
		{"bad valueTemplate", "compile valueTemplate", func(tt *spec) {
			tt.ApiKey.ValueTemplate = "Bearer {{ .Token"
		}},
		{"bad when pattern", "compile when pattern", func(tt *spec) {
			tt.ApiKey.When = &whenSpec{Header: "X-Guard", Pattern: "("}
		}},
		{"credentialRef with neither branch", "neither secret nor credentialProvider", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{}
		}},
		{"credentialRef with both branches", "must not set both", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{
				Secret:             &secretRefSpec{Name: "s"},
				CredentialProvider: &providerRefSpec{Name: "p"},
			}
		}},
		{"empty secret name", "secret.name is empty", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{Secret: &secretRefSpec{}}
		}},
		{"empty provider name", "credentialProvider.name is empty", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{CredentialProvider: &providerRefSpec{}}
		}},
		{"ambiguous provider parameter", "exactly one of value, cel or template", func(tt *spec) {
			tt.CredentialRef = credentialRefSpec{CredentialProvider: &providerRefSpec{
				Name:       "prov",
				Parameters: map[string]valueSourceSpec{"both": {Value: ptr.To("x"), Cel: ptr.To("pod.name")}},
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tt := apiKeyTT()
			tc.mut(tt)
			_, err := parseSpec(t, tt)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	if _, err := parse([]byte(`{"type":123}`)); err == nil {
		t.Fatal("parse accepted a non-string type")
	}
}
