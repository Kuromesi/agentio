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

package model

import "testing"

func TestZTunnelClientClassNames(t *testing.T) {
	if got, want := ClientSharedZTunnel, ClientClass("shared-ztunnel"); got != want {
		t.Fatalf("shared ztunnel client class = %q, want %q", got, want)
	}
	if got, want := ClientDedicatedZTunnel, ClientClass("dedicated-ztunnel"); got != want {
		t.Fatalf("dedicated ztunnel client class = %q, want %q", got, want)
	}
}

func TestPrincipalSPIFFEIdentity(t *testing.T) {
	principal := Principal{
		Kind:        PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "sandbox",
		},
	}
	want := "spiffe://cluster.local/ns/demo/sa/sandbox"
	if got := principal.String(); got != want {
		t.Fatalf("principal = %q, want %q", got, want)
	}
}

func TestPrincipalAgentioTrustDomainRoundTrips(t *testing.T) {
	principal := Principal{
		Kind:        PrincipalServiceAccount,
		TrustDomain: "kube-federating-id@testproj.iam.gserviceaccount.com",
		ServiceAccount: ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "app",
		},
	}
	wantURI := "spiffe://kube-federating-id.testproj.iam.gserviceaccount.com/ns/demo/sa/app"
	if got := principal.String(); got != wantURI {
		t.Fatalf("principal URI = %q, want %q", got, wantURI)
	}
	parsed, err := ParsePrincipal(wantURI, principal.TrustDomain)
	if err != nil {
		t.Fatalf("ParsePrincipal(%q): %v", wantURI, err)
	}
	if parsed != principal {
		t.Fatalf("parsed principal = %#v, want %#v", parsed, principal)
	}
}

func TestPrincipalStringDoesNotNormalizeZeroKind(t *testing.T) {
	principal := Principal{
		TrustDomain: "cluster.local",
		ServiceAccount: ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "sandbox",
		},
	}
	if got := principal.String(); got != "" {
		t.Fatalf("zero-kind Principal string = %q, want empty", got)
	}
}

func TestClientScopeValidateRequiresClassOwnership(t *testing.T) {
	principal := Principal{
		Kind:        PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "agent",
		},
	}
	tests := []struct {
		name  string
		scope ClientScope
		valid bool
	}{
		{"node", ClientScope{Class: ClientSharedZTunnel, Principal: principal, NodeName: "node-a"}, true},
		{"node missing ownership", ClientScope{Class: ClientSharedZTunnel, Principal: principal}, false},
		{"sandbox", ClientScope{Class: ClientDedicatedZTunnel, Principal: principal, SandboxUID: "uid-a"}, true},
		{"sandbox missing ownership", ClientScope{Class: ClientDedicatedZTunnel, Principal: principal}, false},
		{"gateway", ClientScope{Class: ClientEgressGateway, Principal: principal, GatewayKey: "demo/agent"}, true},
		{"gateway missing ownership", ClientScope{Class: ClientEgressGateway, Principal: principal}, false},
		{"gateway wrong namespace", ClientScope{Class: ClientEgressGateway, Principal: principal, GatewayKey: "other/agent"}, false},
		{"gateway wrong service account", ClientScope{Class: ClientEgressGateway, Principal: principal, GatewayKey: "demo/other"}, false},
		{"sandbox invalid principal", ClientScope{Class: ClientDedicatedZTunnel, SandboxUID: "vm-a"}, false},
		{"unknown", ClientScope{Class: "spoofed", Principal: principal, NodeName: "node-a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scope.Validate()
			if tt.valid && err != nil {
				t.Fatalf("valid scope rejected: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
}

func TestPrincipalValidateRejectsIncompleteIdentity(t *testing.T) {
	tests := []Principal{
		{
			ServiceAccount: ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "sandbox",
			},
		},
		{
			Kind: PrincipalServiceAccount,
			ServiceAccount: ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "sandbox",
			},
		},
		{
			Kind:        PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: ServiceAccountRef{
				ServiceAccount: "sandbox",
			},
		},
		{
			Kind:        PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: ServiceAccountRef{
				Namespace: "demo",
			},
		},
		{
			Kind:        "spoofed",
			TrustDomain: "cluster.local",
		},
	}
	for _, principal := range tests {
		if err := principal.Validate(); err == nil {
			t.Fatalf("incomplete principal accepted: %#v", principal)
		}
	}
}

func TestParsePrincipalRoundTrip(t *testing.T) {
	tests := []struct {
		raw  string
		want Principal
	}{
		{
			raw: "spiffe://cluster.local/ns/demo/sa/app",
			want: Principal{
				Kind:        PrincipalServiceAccount,
				TrustDomain: "cluster.local",
				ServiceAccount: ServiceAccountRef{
					Namespace:      "demo",
					ServiceAccount: "app",
				},
			},
		},
	}
	for _, tt := range tests {
		got, err := ParsePrincipal(tt.raw, "cluster.local")
		if err != nil {
			t.Fatalf("ParsePrincipal(%q): %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("ParsePrincipal(%q) = %#v, want %#v", tt.raw, got, tt.want)
		}
		if got.String() != tt.raw {
			t.Fatalf("round trip = %q, want %q", got.String(), tt.raw)
		}
	}
}

func TestParsePrincipalRejectsInvalidIdentities(t *testing.T) {
	tests := []string{
		"",
		"spiffe://other.domain/ns/demo/sa/app",
		"https://cluster.local/ns/demo/sa/app",
		"spiffe://cluster.local/ns/demo/sa/app/extra",
		"spiffe://cluster.local/ns//sa/app",
		"spiffe://cluster.local/ns/demo/sa/",
		"spiffe://cluster.local/sandbox/v2/uid",
		"spiffe://cluster.local/sandbox/v1/uid",
		"spiffe://cluster.local/sandbox/v1/",
		"spiffe://cluster.local/sandbox/v1/bad%2Fuid",
		"spiffe://cluster.local/ns/demo/sa/app?query=1",
		"spiffe://cluster.local/ns/demo/sa/app#fragment",
		"spiffe://user@cluster.local/ns/demo/sa/app",
	}
	for _, raw := range tests {
		if _, err := ParsePrincipal(raw, "cluster.local"); err == nil {
			t.Fatalf("invalid identity accepted: %q", raw)
		}
	}
}
