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
	"fmt"
	"testing"
)

func TestLegacySelfRequestStillRequiresAuthorization(t *testing.T) {
	caller := peerIdentity("demo", "app")
	want := serviceAccountPrincipal("demo", "app")
	for _, allow := range []bool{false, true} {
		authorizer := &fakeDelegatedIdentityAuthorizer{}
		if !allow {
			authorizer.err = fmt.Errorf("Pod binding denied")
		}
		response, err := certificateAuthority(t, caller, authorizer).CreateCertificate(t.Context(), requestWithCSR(t, want.String()))
		if (err == nil) != allow || authorizer.calls != 1 || authorizer.requested != want {
			t.Fatalf("allow=%v err=%v authorizer=%+v", allow, err, authorizer)
		}
		if allow && responseIdentity(t, response) != want.String() {
			t.Fatal("wrong legacy SAN")
		}
	}
}
