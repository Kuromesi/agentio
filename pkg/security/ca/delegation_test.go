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

package ca

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

type fakeDelegatedIdentityAuthorizer struct {
	calls     int
	caller    model.PeerIdentity
	requested model.Principal
	err       error
	authorize func(context.Context, model.PeerIdentity, model.Principal) error
}

func (f *fakeDelegatedIdentityAuthorizer) Authorize(ctx context.Context, caller model.PeerIdentity, requested model.Principal) error {
	f.calls++
	f.caller = caller
	f.requested = requested
	if f.authorize != nil {
		return f.authorize(ctx, caller, requested)
	}
	return f.err
}

func sharedZTunnelCaller() model.PeerIdentity {
	return model.PeerIdentity{
		Principal:  serviceAccountPrincipal("agentio-system", "ztunnel"),
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: "ztunnel-abc",
			WorkloadUID:  "agentio-system/ztunnel-abc",
		},
	}
}

func certificateIdentityForTest(
	t *testing.T,
	authority *Authority,
	ctx context.Context,
	caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
) (model.Principal, error) {
	t.Helper()
	csr, err := parseCertificateRequest(request)
	if err != nil {
		t.Fatalf("parse test certificate request: %v", err)
	}
	return authority.certificateIdentity(ctx, caller, request, csr)
}

func TestDelegatedIdentityDefaultDoesNotUseAuthorizer(t *testing.T) {
	authorizer := &fakeDelegatedIdentityAuthorizer{err: errors.New("must not be called")}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	caller := model.PeerIdentity{
		Principal: serviceAccountPrincipal("demo", "app"),
	}

	got, err := certificateIdentityForTest(t, authority, context.Background(), caller, requestWithCSR(t))
	if err != nil {
		t.Fatalf("own identity refused: %v", err)
	}
	if got != caller.Principal {
		t.Fatalf("identity = %#v, want %#v", got, caller.Principal)
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorizer calls for own identity = %d, want 0", authorizer.calls)
	}
}

// Delegation must go through the authorizer; no Pod source is available here.
func TestDelegatedIdentityUsesAuthorizer(t *testing.T) {
	denied := errors.New("delegation denied")
	authorizer := &fakeDelegatedIdentityAuthorizer{err: denied}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	caller := sharedZTunnelCaller()
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/ns/demo/sa/app")

	_, err := certificateIdentityForTest(t, authority, context.Background(), caller, request)
	if !errors.Is(err, denied) {
		t.Fatalf("delegated authorization error = %v, want %v", err, denied)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
	if authorizer.caller != caller {
		t.Fatalf("authorizer caller = %#v, want %#v", authorizer.caller, caller)
	}
	want := serviceAccountPrincipal("demo", "app")
	if authorizer.requested != want {
		t.Fatalf("authorizer requested principal = %#v, want %#v", authorizer.requested, want)
	}
}

func TestDelegatedIdentityRequiresConfiguredAuthorizer(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/ns/demo/sa/app")
	if _, err := certificateIdentityForTest(t, authority, context.Background(), sharedZTunnelCaller(), request); err == nil {
		t.Fatal("delegated identity was allowed without an authorizer")
	}
}

func TestDelegatedSandboxIdentityIsNotARecognizedPrincipal(t *testing.T) {
	kubernetes := &fakeDelegatedIdentityAuthorizer{}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(attestation.DelegatedIdentityAuthorizers{model.AttestationKubernetes: kubernetes})
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/sandbox/v1/vm-1")

	if _, err := certificateIdentityForTest(t, authority, context.Background(), sharedZTunnelCaller(), request); err == nil {
		t.Fatal("sandbox URI was accepted as a Principal")
	}
	if kubernetes.calls != 0 {
		t.Fatalf("sandbox URI leaked to the Kubernetes authorizer %d times", kubernetes.calls)
	}
}

func TestDelegatedIdentityPassesCancellationToAuthorizer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	authorizer := &fakeDelegatedIdentityAuthorizer{
		authorize: func(ctx context.Context, _ model.PeerIdentity, _ model.Principal) error {
			return ctx.Err()
		},
	}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/ns/demo/sa/app")

	_, err := certificateIdentityForTest(t, authority, ctx, sharedZTunnelCaller(), request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("delegated authorization error = %v, want context canceled", err)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
}

func TestParseSPIFFERejectsMalformedIdentities(t *testing.T) {
	for _, raw := range []string{
		"https://cluster.local/ns/demo/sa/app",
		"spiffe://other.local/ns/demo/sa/app",
		"spiffe://cluster.local/ns/demo",
		"spiffe://cluster.local/ns//sa/app",
		"spiffe://cluster.local/ns/demo/sa/",
		"spiffe://cluster.local/x/demo/sa/app",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := model.ParsePrincipalURL(parsed, "cluster.local"); err == nil {
			t.Fatalf("malformed identity accepted: %s", raw)
		}
	}
}
