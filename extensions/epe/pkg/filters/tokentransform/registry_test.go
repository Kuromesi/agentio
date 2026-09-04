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
	"context"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type stubSigner struct{ shape CredentialKind }

func (s stubSigner) Kind() CredentialKind { return s.shape }
func (s stubSigner) Sign(context.Context, *filter.Stream, []byte, *inputs.Scope, Credential, any) ([]filter.Mutation, error) {
	return nil, nil
}

func TestRegisterSignerAndLookup(t *testing.T) {
	t.Cleanup(swapSigners())

	RegisterSigner("TestType", stubSigner{shape: CredentialKindToken})

	if !HasSigner("TestType") {
		t.Error("HasSigner(TestType) = false after registration")
	}
	if HasSigner("Other") {
		t.Error("HasSigner(Other) = true for an unregistered type")
	}
	m := signerMap()
	if len(m) != 1 || m["TestType"].Kind() != CredentialKindToken {
		t.Errorf("signerMap() = %v, want one TestType signer with CredentialKindToken", m)
	}
}

func TestRegisterSignerDuplicatePanics(t *testing.T) {
	t.Cleanup(swapSigners())
	RegisterSigner("Dup", stubSigner{})
	defer func() {
		if recover() == nil {
			t.Error("duplicate RegisterSigner did not panic")
		}
	}()
	RegisterSigner("Dup", stubSigner{})
}
