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
	"fmt"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
)

// A trailing newline is what `kubectl create secret --from-file` produces from
// any ordinary text file, and Envoy rejects a header mutation whose value
// contains CR or LF (MutationUtils::applyHeaderMutations ->
// header_mutation_set_contains_invalid_character), answering with the
// status_on_error local reply — HTTP 500 by default — on every request the rule
// matches. The credential must therefore be trimmed before it reaches a
// mutation.
func TestFilter_TrailingNewlineInSecretIsTrimmed(t *testing.T) {
	secret := &fakeSource{cred: Credential{Token: "sk-abc123\n"}}
	f := newTestFilter(secret, nil, secretCfg(true))

	act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	muts := act.Mutations()
	if len(muts) == 0 {
		t.Fatalf("no mutations produced: %+v", act)
	}
	for _, m := range muts {
		for _, op := range m.HeaderOps {
			if strings.ContainsAny(op.Value, "\r\n") {
				t.Fatalf("header %q carries a CR/LF that Envoy will reject: %q", op.Name, op.Value)
			}
			if op.Kind == filter.HeaderSet && op.Value != "Bearer sk-abc123" {
				t.Errorf("header %q = %q, want %q", op.Name, op.Value, "Bearer sk-abc123")
			}
		}
	}
}

// Surrounding whitespace of every kind is trimmed, on every credential field.
func TestCredentialSanitized_TrimsSurroundingWhitespace(t *testing.T) {
	got, err := Credential{
		Token:           " tok\n",
		AccessKeyID:     "\tAK\r\n",
		AccessKeySecret: "SK \n",
		SecurityToken:   "\nSTS",
	}.sanitized()
	if err != nil {
		t.Fatalf("sanitized: %v", err)
	}
	want := Credential{Token: "tok", AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "STS"}
	if got != want {
		t.Errorf("sanitized = %+v, want %+v", got, want)
	}
}

// An interior CR/LF cannot be trimmed away, and forwarding it would let a
// credential store inject a header break. It is a hard error instead.
func TestCredentialSanitized_RejectsInteriorControlBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cred Credential
	}{
		{"newline in token", Credential{Token: "sk-abc\ndef"}},
		{"carriage return in token", Credential{Token: "sk-abc\rdef"}},
		{"header injection attempt", Credential{Token: "sk\r\nx-injected: 1"}},
		{"newline in access key id", Credential{AccessKeyID: "A\nK"}},
		{"NUL in security token", Credential{SecurityToken: "ST\x00S"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.cred.sanitized(); err == nil {
				t.Fatal("want an error for an unusable credential value, got nil")
			}
		})
	}
}

// A credential that needs no cleaning passes through byte-identically.
func TestCredentialSanitized_LeavesCleanValuesAlone(t *testing.T) {
	in := Credential{Token: "sk-abc123", AccessKeyID: "AK", AccessKeySecret: "SK/+=", SecurityToken: "STS"}
	got, err := in.sanitized()
	if err != nil {
		t.Fatalf("sanitized: %v", err)
	}
	if got != in {
		t.Errorf("sanitized = %+v, want it unchanged %+v", got, in)
	}
}

// The deny body reaches an untrusted client, so it must not carry the internal
// failure text: Secret names, Kubernetes RBAC messages and credential-provider
// errors all flow through this path (RBAC especially, now that a denied read
// resolves through failStrategy). Operators get the detail from the logged
// error instead.
func TestBlockReply_DoesNotLeakInternalDetail(t *testing.T) {
	leaky := fmt.Errorf(`%w: secrets "sts-creds" is forbidden: User "system:serviceaccount:x:y" cannot get resource "secrets"`, ErrNoPermission)
	reply, ok := blockReply(leaky).Reply()
	if !ok {
		t.Fatal("blockReply did not produce a Reply")
	}
	body := string(reply.Body)

	for _, secret := range []string{"sts-creds", "serviceaccount", "forbidden", "cannot get resource"} {
		if strings.Contains(body, secret) {
			t.Errorf("deny body leaks %q to the client: %q", secret, body)
		}
	}
	if body == "" {
		t.Error("deny body is empty; the client should still get a usable reason")
	}
}

// The signer touches only the target header, and nothing else — no removal of
// the caller's own credential header. That is deliberate for compatibility: a
// caller may rely on both its Authorization and the injected header reaching
// the upstream, and no configuration uses a non-default targetHeader today.
// This test exists so the behaviour cannot change silently; tightening it needs
// an explicit policy knob, not a new default.
func TestApiKeySigner_TouchesOnlyTheTargetHeader(t *testing.T) {
	tmpl, err := eval.CompileTemplate("valueTemplate", "{{ .Token }}")
	if err != nil {
		t.Fatalf("CompileTemplate: %v", err)
	}
	muts, err := apiKeySigner{}.Sign(context.Background(), nil, nil, nil,
		Credential{Token: "sk-injected"},
		PreparedApiKeyConfig{Headers: []PreparedHeader{{
			Name: "x-api-key", Value: HeaderValueSource{Template: tmpl},
		}}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var ops []filter.HeaderOp
	for _, m := range muts {
		ops = append(ops, m.HeaderOps...)
	}
	if len(ops) != 1 {
		t.Fatalf("got %d header ops, want exactly 1: %+v", len(ops), ops)
	}
	if ops[0].Kind != filter.HeaderSet || ops[0].Name != "x-api-key" {
		t.Errorf("op = %+v, want a set of x-api-key", ops[0])
	}
}

// An interior control byte must be surfaced through the rule's failStrategy
// rather than producing a broken mutation.
func TestFilter_InteriorNewlineInSecretIsBlocked(t *testing.T) {
	secret := &fakeSource{cred: Credential{Token: "sk\r\nx-injected: 1"}}
	f := newTestFilter(secret, nil, secretCfg(true))

	act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	if act.Kind() != filter.KindStop {
		t.Fatalf("Kind = %v, want KindStop under failStrategy=Block", act.Kind())
	}
}
