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

// schema.go is tokentransform's payload contract: the JSON document a
// policy source must produce, and the only place the filter's config is
// built. The vocabulary is the filter's own — Type is a signer-registry
// key, and credentialRef is the typed union only. A policy API that also
// accepts deprecated spellings normalizes them away before the document
// gets here, which is why this file names no API package.
package tokentransform

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
)

// The failStrategy values that let a failed transformation through. Everything
// else blocks, including an empty or unrecognized value: the CRD defaults the
// field to Block, so an empty one means the payload skipped API-server
// defaulting, and failing closed matches the filter's fail-closed convention.
const (
	failStrategyAllow  = "Allow"
	failStrategyIgnore = "Ignore"
)

// spec is the wire form of a tokentransform payload. Tags mirror the
// SecurityProfile CRD's TokenTransformationAction so a CRD-shaped document
// parses unchanged, minus `disabled`: an open payload map
// says "off" by omitting the key, so the policy side absorbs that field
// rather than passing it through. Tags are explicit
// because renaming a Go field must never silently change the wire.
type spec struct {
	FailStrategy  string            `json:"failStrategy,omitempty"`
	Type          string            `json:"type,omitempty"`
	CredentialRef credentialRefSpec `json:"credentialRef"`
	ApiKey        *apiKeySpec       `json:"apiKey,omitempty"`
}

// credentialRefSpec is the typed union; exactly one branch must be set.
type credentialRefSpec struct {
	Secret             *secretRefSpec   `json:"secret,omitempty"`
	CredentialProvider *providerRefSpec `json:"credentialProvider,omitempty"`
}

type secretRefSpec struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type providerRefSpec struct {
	Name       string                     `json:"name,omitempty"`
	Parameters map[string]valueSourceSpec `json:"parameters,omitempty"`
}

// valueSourceSpec is one provider parameter; exactly one field must be set.
type valueSourceSpec struct {
	Value    *string `json:"value,omitempty"`
	Cel      *string `json:"cel,omitempty"`
	Template *string `json:"template,omitempty"`
}

type apiKeySpec struct {
	When          *whenSpec `json:"when,omitempty"`
	TargetHeader  string    `json:"targetHeader,omitempty"`
	ValueTemplate string    `json:"valueTemplate,omitempty"`
}

type whenSpec struct {
	Header  string `json:"header,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// parse compiles one payload document into the filter config. Templates,
// CEL programs and regexps are compiled here — once per profile version,
// never per request. A type with no registered signer fails closed here
// rather than at request time, so silent fail-open is structurally
// impossible.
func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}

	key := s.Type
	if key == "" {
		key = TypeAPIKey
	}
	if !HasSigner(key) {
		return Config{}, fmt.Errorf("token transformation type %q has no signer in this build", s.Type)
	}

	cfg := Config{
		Type:      key,
		FailBlock: s.FailStrategy != failStrategyAllow && s.FailStrategy != failStrategyIgnore,
	}

	source, err := parseSource(s.CredentialRef)
	if err != nil {
		return Config{}, err
	}
	cfg.Source = source

	if key == TypeAPIKey {
		if s.ApiKey == nil {
			return Config{}, fmt.Errorf("apiKey config is nil")
		}
		tmpl, err := eval.CompileTemplate("valueTemplate", s.ApiKey.ValueTemplate)
		if err != nil {
			return Config{}, fmt.Errorf("compile valueTemplate: %w", err)
		}
		// Canonicalized here, once per profile version, rather than on every
		// request: see ApiKeyConfig.
		cfg.SignerCfg = ApiKeyConfig{
			TargetHeader: strings.ToLower(s.ApiKey.TargetHeader),
			Template:     tmpl,
		}
		if s.ApiKey.When != nil {
			re, err := regexp.Compile(s.ApiKey.When.Pattern)
			if err != nil {
				return Config{}, fmt.Errorf("compile when pattern %q: %w", s.ApiKey.When.Pattern, err)
			}
			cfg.When = &When{Header: s.ApiKey.When.Header, Re: re}
		}
	}
	return cfg, nil
}

// parseSource resolves the credentialRef union into the filter's own
// SourceSpec. Neither branch set is as malformed as both: a payload that
// names no credential cannot be served, and guessing a default would be a
// silent fail-open.
func parseSource(ref credentialRefSpec) (SourceSpec, error) {
	hasSecret := ref.Secret != nil
	hasProvider := ref.CredentialProvider != nil
	switch {
	case hasSecret && hasProvider:
		return SourceSpec{}, fmt.Errorf("credentialRef must not set both secret and credentialProvider")
	case hasSecret:
		if ref.Secret.Name == "" {
			return SourceSpec{}, fmt.Errorf("credentialRef.secret.name is empty")
		}
		return SourceSpec{
			Kind: SourceKindSecret, Name: ref.Secret.Name, Namespace: ref.Secret.Namespace,
		}, nil
	case hasProvider:
		if ref.CredentialProvider.Name == "" {
			return SourceSpec{}, fmt.Errorf("credentialRef.credentialProvider.name is empty")
		}
		params, err := compileParams(ref.CredentialProvider.Parameters)
		if err != nil {
			return SourceSpec{}, err
		}
		return SourceSpec{
			Kind: SourceKindProvider, Name: ref.CredentialProvider.Name, Parameters: params,
		}, nil
	default:
		return SourceSpec{}, fmt.Errorf("credentialRef sets neither secret nor credentialProvider")
	}
}

// compileParams pre-compiles credentialProvider parameter sources; a
// compile failure is a malformed payload and fails closed at parse time.
func compileParams(parameters map[string]valueSourceSpec) (map[string]ParamSource, error) {
	if len(parameters) == 0 {
		return nil, nil
	}
	out := make(map[string]ParamSource, len(parameters))
	for name, source := range parameters {
		count := 0
		if source.Value != nil {
			count++
		}
		if source.Cel != nil {
			count++
		}
		if source.Template != nil {
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf("credential parameter %q: exactly one of value, cel or template must be set", name)
		}
		var ps ParamSource
		switch {
		case source.Value != nil:
			v := *source.Value
			ps.Value = &v
		case source.Template != nil:
			tmpl, err := eval.CompileTemplate("credentialParameter", *source.Template)
			if err != nil {
				return nil, fmt.Errorf("credential parameter %q: %w", name, err)
			}
			ps.Template = tmpl
		default:
			prog, err := eval.CompileValue(*source.Cel)
			if err != nil {
				return nil, fmt.Errorf("credential parameter %q: %w", name, err)
			}
			ps.Cel = prog
		}
		out[name] = ps
	}
	return out, nil
}

// NewDefinition returns a token-transform definition with its dependencies frozen.
func NewDefinition(deps Deps) filter.Definition {
	return filter.Define(NewDescriptor(deps), parse)
}
