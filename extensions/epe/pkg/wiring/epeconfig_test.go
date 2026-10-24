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

package wiring

import (
	"slices"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
)

func TestDefaultEPEConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		source   string
	}{
		{name: "without credential provider", source: "invalid"},
		{name: "HTTP credential provider", endpoint: "http://credentials.example", source: credProviderSourceNone},
		{name: "HTTPS credential provider", endpoint: "https://credentials.example", source: credProviderSourceNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testsupport.SetForTest(t, &identityProviderURL, tc.endpoint)
			testsupport.SetForTest(t, &credProviderMTLSSource, tc.source)
			cfg, err := DefaultEPEConfig()
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.GetEgressAuthorization().GetDeniedCidrs(); !slices.Equal(
				got, []string{
					"127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128",
					"169.254.0.0/16", "fe80::/10",
				},
			) {
				t.Fatalf("missing built-in destination restrictions: %v", got)
			}
			if tc.endpoint == "" {
				if len(cfg.ExtensionProviders) != 0 || cfg.DefaultProviders != nil {
					t.Fatal("an unset endpoint must not create an unusable default provider")
				}
				return
			}
			if len(cfg.ExtensionProviders) != 1 || cfg.ExtensionProviders[0].Name != defaultCredentialProviderName ||
				cfg.GetDefaultProviders().GetCredentialProvider() != defaultCredentialProviderName ||
				cfg.ExtensionProviders[0].GetCredentialProvider().GetUrl() != tc.endpoint {
				t.Fatalf("missing default credential provider registration: %v", cfg)
			}
		})
	}
}

func TestDefaultEPEConfigRejectsInvalidProvider(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		source   string
		want     string
	}{
		{name: "invalid endpoint", endpoint: "not-a-url", source: credProviderSourceNone, want: "requires an absolute HTTP(S) URL"},
		{name: "invalid TLS source", endpoint: "https://credentials.example", source: "invalid", want: "not one of secret or none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testsupport.SetForTest(t, &identityProviderURL, tc.endpoint)
			testsupport.SetForTest(t, &credProviderMTLSSource, tc.source)
			_, err := DefaultEPEConfig()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestApplyEPEConfigAppendsMandatoryRestrictions(t *testing.T) {
	testsupport.SetForTest(t, &identityProviderURL, "")
	base, err := DefaultEPEConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ApplyEPEConfig("egressAuthorization: {deniedCIDRs: [192.0.2.10/32]}", base)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"192.0.2.10/32"}, base.EgressAuthorization.DeniedCidrs...)
	if !slices.Equal(cfg.EgressAuthorization.DeniedCidrs, want) {
		t.Fatalf(
			"effective restrictions=%v, want user entries followed by built-ins %v",
			cfg.EgressAuthorization.DeniedCidrs,
			want,
		)
	}
	// An inherited list must not grow on each layer or duplicate user-supplied built-ins.
	inherited, err := ApplyEPEConfig("egressAuthorization: null", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inherited.EgressAuthorization.DeniedCidrs, want) {
		t.Fatalf("inherited restrictions changed: %v", inherited.EgressAuthorization.DeniedCidrs)
	}
	cleared, err := ApplyEPEConfig("egressAuthorization: {deniedCIDRs: []}", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cleared.EgressAuthorization.DeniedCidrs, base.EgressAuthorization.DeniedCidrs) {
		t.Fatalf("clearing user entries removed mandatory restrictions: %v", cleared.EgressAuthorization.DeniedCidrs)
	}
	if !slices.Equal(cfg.EgressAuthorization.DeniedCidrs, want) {
		t.Fatal("applying a new layer mutated the previous configuration")
	}
}
