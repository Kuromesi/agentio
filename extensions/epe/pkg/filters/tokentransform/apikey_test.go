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

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestApiKeySignerInjectsRenderedHeader(t *testing.T) {
	tmpl, err := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }} / {{ .Pod.Namespace }}")
	if err != nil {
		t.Fatal(err)
	}
	scope := &inputs.Scope{Pod: inputs.Pod{Namespace: "team-a"}}
	muts, err := (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, nil, scope,
		Credential{Token: "tok-1"}, ApiKeyConfig{TargetHeader: "authorization", Template: tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(muts) != 1 || len(muts[0].HeaderOps) != 1 ||
		muts[0].HeaderOps[0].Kind != filter.HeaderSet ||
		muts[0].HeaderOps[0].Name != "authorization" ||
		muts[0].HeaderOps[0].Value != "Bearer tok-1 / team-a" {
		t.Fatalf("muts = %+v", muts)
	}
}

// An empty TargetHeader must fall back to Authorization rather than emit a
// header op with an empty name. The CRD defaults the field
// (+kubebuilder:default:="Authorization"), so an empty value means the config
// skipped API-server defaulting.
func TestApiKeySignerDefaultsTargetHeader(t *testing.T) {
	tmpl, err := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }}")
	if err != nil {
		t.Fatal(err)
	}
	muts, err := (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, nil, nil,
		Credential{Token: "tok-1"}, ApiKeyConfig{Template: tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(muts) != 1 || len(muts[0].HeaderOps) != 1 {
		t.Fatalf("muts = %+v, want one header op", muts)
	}
	if got := muts[0].HeaderOps[0].Name; got != DefaultTargetHeader {
		t.Errorf("header name = %q, want %q", got, DefaultTargetHeader)
	}
	if got := muts[0].HeaderOps[0].Value; got != "Bearer tok-1" {
		t.Errorf("header value = %q", got)
	}
}

func TestAPIKeySignerKind(t *testing.T) {
	if (apiKeySigner{}).Kind() != CredentialKindToken {
		t.Fatal("apiKeySigner must declare CredentialKindToken")
	}
}

func TestApiKeySignerRejectsForeignConfig(t *testing.T) {
	if _, err := (apiKeySigner{}).Sign(context.Background(), &filter.Stream{}, nil, nil, Credential{}, "not-mine"); err == nil {
		t.Fatal("foreign config must error")
	}
}
