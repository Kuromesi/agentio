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
	"bytes"
	"context"
	"fmt"
	"text/template"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func init() { RegisterSigner(TypeAPIKey, apiKeySigner{}) }

// DefaultTargetHeader is the header the ApiKey signer overwrites when the
// config does not name one. It mirrors the CRD's own default, so a config
// that skipped API-server defaulting still injects somewhere meaningful
// instead of emitting a header op with an empty name.
//
// Spelled lower-case even though the CRD default reads "Authorization":
// header names are case-insensitive and Envoy lower-cases them anyway, while
// the engine's mutation fold lower-cases every key it folds — and
// strings.ToLower only allocates when the input is not already lower-case.
// Emitting the canonical spelling keeps that fold allocation-free on every
// request that injects a token.
const DefaultTargetHeader = "authorization"

// ApiKeyConfig is the projected per-unit config of the built-in ApiKey
// signer: which header to overwrite and the compiled value template. An
// empty TargetHeader means DefaultTargetHeader.
//
// TargetHeader is canonicalized to lower-case when the payload is parsed,
// so the request path never lower-cases it again.
type ApiKeyConfig struct {
	TargetHeader string
	Template     *template.Template
}

// ApiKeyTemplateData is the data visible to value templates. Exported names
// are policy-visible: existing profiles' templates reference them.
type ApiKeyTemplateData struct {
	Token string
	Pod   inputs.Pod
	scope *inputs.Scope
}

// Inputs resolves lazily through the scope so that, like every other
// template site, only a template that actually reads .Inputs fails when the
// profile's inputs are unavailable; text/template aborts on the error.
func (d ApiKeyTemplateData) Inputs() (map[string]any, error) {
	if d.scope == nil {
		return nil, nil
	}
	return d.scope.Inputs()
}

// apiKeySigner injects a credential token into one request header — the
// OSS default transformation, always registered.
type apiKeySigner struct{}

func (apiKeySigner) Kind() CredentialKind { return CredentialKindToken }

func (apiKeySigner) Sign(_ context.Context, _ *filter.Stream, _ []byte, scope *inputs.Scope, cred Credential, cfg any) ([]filter.Mutation, error) {
	ac, ok := cfg.(ApiKeyConfig)
	if !ok {
		return nil, fmt.Errorf("apikey signer: config is %T, want ApiKeyConfig", cfg)
	}
	data := ApiKeyTemplateData{Token: cred.Token}
	if scope != nil {
		data.Pod = scope.Pod()
		data.scope = scope
	}
	var buf bytes.Buffer
	if err := ac.Template.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render value template: %w", err)
	}
	header := ac.TargetHeader
	if header == "" {
		header = DefaultTargetHeader
	}
	// Only the target header is touched. When it is Authorization — the default
	// — the set overwrites whatever credential the caller sent. When it is some
	// other header, the caller's Authorization is forwarded alongside the
	// injected value, so an upstream that consults Authorization first may
	// authenticate with the caller's own credential instead. That is deliberate:
	// stripping it would change behavior for callers that rely on both headers
	// reaching the upstream, so any change belongs behind an explicit policy
	// knob rather than a silent default change.
	return []filter.Mutation{filter.SetHeader(header, buf.String())}, nil
}
