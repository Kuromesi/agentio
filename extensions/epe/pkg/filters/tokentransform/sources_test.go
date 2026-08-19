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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/credential"
)

func secretObj(ns, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: data}
}

func TestSecretSourceTokenKind(t *testing.T) {
	src := NewSecretSource(k8sfake.NewClientset(secretObj("ns1", "s", map[string][]byte{"apiKey": []byte("k-1")})))
	cred, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken, Name: "s", Namespace: "ns1"})
	if err != nil || cred.Token != "k-1" {
		t.Fatalf("Fetch = %q, %v; want token k-1", cred.Token, err)
	}
}

func TestSecretSourceSTSKind(t *testing.T) {
	src := NewSecretSource(k8sfake.NewClientset(secretObj("ns1", "s", map[string][]byte{
		"accessKeyId": []byte("ak"), "accessKeySecret": []byte("sk"), "securityToken": []byte("tok"),
	})))
	cred, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindSTS, Name: "s", Namespace: "ns1"})
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessKeyID != "ak" || cred.AccessKeySecret != "sk" || cred.SecurityToken != "tok" {
		t.Fatalf("triplet = %+v", cred)
	}
}

func TestSecretSourceMissingKey(t *testing.T) {
	src := NewSecretSource(k8sfake.NewClientset(secretObj("ns1", "s", map[string][]byte{})))
	_, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken, Name: "s", Namespace: "ns1"})
	if err == nil || !strings.Contains(err.Error(), `missing data key "apiKey"`) {
		t.Fatalf("err = %v, want missing data key", err)
	}
}

func TestSecretSourceNotFound(t *testing.T) {
	src := NewSecretSource(k8sfake.NewClientset())
	_, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken, Name: "gone", Namespace: "ns1"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not found", err)
	}
}

func TestSecretSourceUnconfigured(t *testing.T) {
	src := NewSecretSource(nil)
	if _, err := src.Fetch(context.Background(), Ref{}); err == nil {
		t.Fatal("nil clientset must error")
	}
}

type fakeTokenProvider struct {
	token string
	err   error
}

func (f *fakeTokenProvider) GetTokenWithExtraMetadata(context.Context, string, string, string, map[string]any) (string, error) {
	return f.token, f.err
}

type fakeSTSProvider struct {
	cred credential.STSCredential
	err  error
}

func (f *fakeSTSProvider) GetSTSCredentialWithExtraMetadata(context.Context, string, string, string, map[string]any) (credential.STSCredential, error) {
	return f.cred, f.err
}

func TestProviderSourceTokenKind(t *testing.T) {
	src := NewProviderSource(&fakeTokenProvider{token: "prov-token"}, nil)
	cred, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken, Name: "prov", AccessToken: "at", SandboxClientID: "cid"})
	if err != nil || cred.Token != "prov-token" {
		t.Fatalf("Fetch = %q, %v", cred.Token, err)
	}
}

func TestProviderSourceSTSKind(t *testing.T) {
	sts := credential.STSCredential{AccessKeyID: "ak", AccessKeySecret: "sk", SecurityToken: "tok"}
	src := NewProviderSource(nil, &fakeSTSProvider{cred: sts})
	cred, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindSTS, Name: "prov", AccessToken: "at"})
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessKeyID != "ak" || cred.AccessKeySecret != "sk" || cred.SecurityToken != "tok" {
		t.Fatalf("triplet = %+v", cred)
	}
}

func TestProviderSourceEmptyName(t *testing.T) {
	src := NewProviderSource(&fakeTokenProvider{token: "x"}, nil)
	_, err := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want empty provider name error", err)
	}
}

func TestProviderSourceUnconfigured(t *testing.T) {
	src := NewProviderSource(nil, nil)
	_, errTok := src.Fetch(context.Background(), Ref{Kind: CredentialKindToken, Name: "p"})
	_, errSTS := src.Fetch(context.Background(), Ref{Kind: CredentialKindSTS, Name: "p"})
	if errTok == nil || errSTS == nil {
		t.Fatal("nil clients must error")
	}
}
