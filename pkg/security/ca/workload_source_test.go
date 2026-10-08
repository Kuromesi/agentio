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

// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

// PEN 32473 is reserved for examples; it is not a production default.
var testWorkloadSourceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}

func TestCertificateSignsAuthorizedSourceOnly(t *testing.T) {
	principal := serviceAccountPrincipal("demo", "shared")
	request := requestWithCSR(t, principal.String())
	csr, err := parseCertificateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	// Even a signed CSR cannot supply the extension's claims or criticality.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr.ExtraExtensions = []pkix.Extension{{Id: testWorkloadSourceOID, Critical: true, Value: []byte("forged")}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	request.Csr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	for _, tc := range []struct {
		name       string
		podUID     string
		configured bool
	}{
		{"instance a", "pod-a", true},
		{"instance b with same URI", "pod-b", true},
		{"old request with OID configured", "", true},
		{"old request without OID configured", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{}
			authority := certificateAuthority(t, sharedZTunnelCaller(), authorizer)
			if tc.configured {
				authority.workloadSourceOID = testWorkloadSourceOID
			}
			metadata := map[string]any{impersonatedIdentityMetadata: principal.String()}
			var source model.SourceRef
			if tc.podUID != "" {
				source = model.SourceRef{Registry: "kubernetes/test", Key: tc.podUID}
				metadata[targetWorkloadMetadata] = map[string]any{"registry": source.Registry, "key": source.Key}
			}
			request.Metadata, err = structpb.NewStruct(metadata)
			if err != nil {
				t.Fatal(err)
			}
			response, err := authority.CreateCertificate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if got := responseIdentity(t, response); got != principal.String() {
				t.Fatalf("URI SAN = %s, want %s", got, principal.String())
			}
			if authorizer.calls != 1 || authorizer.requested != principal || authorizer.source != source {
				t.Fatalf("authorization received principal=%v source=%v", authorizer.requested, authorizer.source)
			}
			block, _ := pem.Decode([]byte(response.CertChain[0]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, extension := range cert.Extensions {
				if !extension.Id.Equal(testWorkloadSourceOID) {
					continue
				}
				found = true
				var got struct {
					Registry string `asn1:"utf8"`
					Key      string `asn1:"utf8"`
				}
				rest, err := asn1.Unmarshal(extension.Value, &got)
				if err != nil || len(rest) != 0 || extension.Critical || got.Registry != source.Registry ||
					got.Key != source.Key {
					t.Fatalf("unexpected source extension: %+v payload=%+v err=%v", extension, got, err)
				}
			}
			if found != (tc.podUID != "") {
				t.Fatalf("source extension present=%v, requested source=%+v", found, source)
			}
		})
	}
}

func TestCertificateTargetWorkloadFailsWithoutDowngrade(t *testing.T) {
	valid := map[string]any{"registry": "kubernetes/test", "key": "pod-a"}
	for _, tc := range []struct {
		name        string
		value       any
		configured  bool
		denied      bool
		code        codes.Code
		authorizers int
	}{
		{"null", nil, true, false, codes.Unauthenticated, 0},
		{"string", "pod-a", true, false, codes.Unauthenticated, 0},
		{"empty object", map[string]any{}, true, false, codes.Unauthenticated, 0},
		{"missing registry", map[string]any{"key": "pod-a"}, true, false, codes.Unauthenticated, 0},
		{"non-string key", map[string]any{"registry": "kubernetes/test", "key": 1}, true, false, codes.Unauthenticated, 0},
		{"empty key", map[string]any{"registry": "kubernetes/test", "key": ""}, true, false, codes.Unauthenticated, 0},
		{"authorization denied", valid, true, true, codes.Unauthenticated, 1},
		{"extension not configured", valid, false, false, codes.FailedPrecondition, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{}
			if tc.denied {
				authorizer.err = errors.New("source is not owned by caller")
			}
			authority := certificateAuthority(t, peerIdentity("demo", "shared"), authorizer)
			if tc.configured {
				authority.workloadSourceOID = testWorkloadSourceOID
			}
			request := requestWithCSR(t)
			metadata, err := structpb.NewStruct(map[string]any{targetWorkloadMetadata: tc.value})
			if err != nil {
				t.Fatal(err)
			}
			request.Metadata = metadata
			response, err := authority.CreateCertificate(t.Context(), request)
			if response != nil || status.Code(err) != tc.code || authorizer.calls != tc.authorizers {
				t.Fatalf("response=%v err=%v authorizer calls=%d", response, err, authorizer.calls)
			}
		})
	}
}

func TestWorkloadSourceOIDConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true},
		{testWorkloadSourceOID.String(), true},
		{"2.5.29.17", false},
		{"1.3.6.1.4.1.", false},
		{"1.3.6.1.4.1.invalid", false},
		{"1.3.6.1.4.1.32473.2147483648", false},
	} {
		oid, err := parseWorkloadSourceOID(tc.value)
		if (err == nil) != tc.valid {
			t.Errorf("parseWorkloadSourceOID(%q) = %v, %v", tc.value, oid, err)
		}
		if tc.valid && tc.value != "" && oid.String() != tc.value {
			t.Errorf("OID changed: %s, want %s", oid, tc.value)
		}
	}
}

func TestCertificateSourceRequiresAuthorizer(t *testing.T) {
	authority := certificateAuthority(t, peerIdentity("demo", "shared"), nil)
	authority.workloadSourceOID = testWorkloadSourceOID
	request := requestWithCSR(t)
	metadata, err := structpb.NewStruct(map[string]any{
		targetWorkloadMetadata: map[string]any{"registry": "kubernetes/test", "key": "pod-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata = metadata
	if response, err := authority.CreateCertificate(t.Context(), request); response != nil ||
		status.Code(err) != codes.Unauthenticated {
		t.Fatalf("instance request without authorizer: response=%v err=%v", response, err)
	}
}

func TestSelfRequestSourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
		bound      bool
		denied     bool
	}{
		{"bound self", true, true, false},
		{"extension disabled", false, true, false},
		{"unbound self", true, false, false},
		{"source authorization denied", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := peerIdentity("demo", "app")
			if tc.bound {
				caller.Kubernetes.WorkloadName = "app-pod"
				caller.Kubernetes.WorkloadUID = "pod-a"
			}
			authorizer := &fakeDelegatedIdentityAuthorizer{}
			if tc.denied {
				authorizer.err = errors.New("Pod binding no longer valid")
			}
			authority := certificateAuthority(t, caller, authorizer)
			authority.options.ClusterID = "test"
			if tc.configured {
				authority.workloadSourceOID = testWorkloadSourceOID
			}
			principal := serviceAccountPrincipal("demo", "app")
			response, err := authority.CreateCertificate(t.Context(), requestWithCSR(t, principal.String()))
			wantSource := tc.configured && tc.bound
			wantCalls := 0
			if wantSource {
				wantCalls = 1
			}
			if authorizer.calls != wantCalls {
				t.Fatalf("authorization calls=%d, want %d", authorizer.calls, wantCalls)
			}
			if wantSource && authorizer.source != (model.SourceRef{Registry: "kubernetes/test", Key: "pod-a"}) {
				t.Fatalf("authorized source=%+v", authorizer.source)
			}
			if tc.denied {
				if response != nil || status.Code(err) != codes.Unauthenticated {
					t.Fatalf("response=%v err=%v", response, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := responseIdentity(t, response); got != principal.String() {
				t.Fatalf("identity=%s", got)
			}
			block, _ := pem.Decode([]byte(response.CertChain[0]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, extension := range cert.Extensions {
				if !extension.Id.Equal(testWorkloadSourceOID) {
					continue
				}
				found = true
				var source struct {
					Registry string `asn1:"utf8"`
					Key      string `asn1:"utf8"`
				}
				rest, err := asn1.Unmarshal(extension.Value, &source)
				if err != nil || len(rest) != 0 || extension.Critical || source.Registry != "kubernetes/test" ||
					source.Key != "pod-a" {
					t.Fatalf("source=%+v critical=%v err=%v", source, extension.Critical, err)
				}
			}
			if found != wantSource {
				t.Fatalf("extension present=%v, want %v", found, wantSource)
			}
		})
	}
}
