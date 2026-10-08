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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWorkloadCertificateRejectsIdentityConflict(t *testing.T) {
	principal := mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/pod-a")
	other := mustTestPrincipal("cluster.local", "cluster/test/ns/demo/workload/pod-b")
	authorizer := &fakeDelegatedIdentityAuthorizer{}
	authority := certificateAuthority(t, sharedZTunnelCaller(), authorizer)
	request := requestWithCSR(t, principal.String())
	setRequestMetadata(t, request, other.String())
	response, err := authority.CreateCertificate(t.Context(), request)
	if response != nil || status.Code(err) != codes.Unauthenticated || authorizer.calls != 0 {
		t.Fatalf("response=%v err=%v authorization calls=%d", response, err, authorizer.calls)
	}
}

func TestWorkloadSelfRequestRequiresAuthorization(t *testing.T) {
	for _, authorizer := range []*fakeDelegatedIdentityAuthorizer{nil, {err: errors.New("Pod binding is invalid")}} {
		authority := certificateAuthority(t, peerIdentity("demo", "shared"), authorizer)
		request := requestWithCSR(t, "spiffe://cluster.local/cluster/test/ns/demo/workload/pod-a")
		response, err := authority.CreateCertificate(t.Context(), request)
		if response != nil || status.Code(err) != codes.Unauthenticated {
			t.Fatalf("response=%v err=%v", response, err)
		}
	}
}

func TestCertificateRequestsSupportOldAndNewIdentities(t *testing.T) {
	caller := peerIdentity("demo", "app")
	oldID := "spiffe://cluster.local/ns/demo/sa/app"
	newID := "spiffe://cluster.local/cluster/test/ns/demo/workload/pod-a"
	for _, tc := range []struct {
		name         string
		csr          string
		impersonated string
		want         string
		calls        int
	}{
		{"old self", oldID, "", oldID, 0},
		{"old self without SAN", "", "", oldID, 0},
		{"new self", newID, "", newID, 1},
		{"old delegated", oldID, oldID, oldID, 1},
		{"new delegated", newID, newID, newID, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{}
			authority := certificateAuthority(t, caller, authorizer)
			request := requestWithCSR(t)
			if tc.csr != "" {
				request = requestWithCSR(t, tc.csr)
			}
			if tc.impersonated != "" {
				setRequestMetadata(t, request, tc.impersonated)
			}
			response, err := authority.CreateCertificate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if responseIdentity(t, response) != tc.want || authorizer.calls != tc.calls {
				t.Fatalf("unexpected certificate or authorization count: %+v", authorizer)
			}
			if tc.calls > 0 && authorizer.requested.String() != tc.want {
				t.Fatalf("authorized principal=%s, want %s", authorizer.requested, tc.want)
			}
		})
	}
}
