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
	"text/template"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
	"golang.org/x/net/http/httpguts"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func init() { RegisterSigner(TypeAPIKey, apiKeySigner{}) }

// DefaultTargetHeader is the header the ApiKey signer overwrites when the
// legacy config does not name one. The API no longer materializes this value
// through CRD defaulting; the signer preserves the released legacy behavior
// so existing profiles that omit targetHeader still target Authorization.
//
// Spelled lower-case because header names are case-insensitive and Envoy
// lower-cases them anyway, while the engine's mutation fold lower-cases every
// key it folds — and strings.ToLower only allocates when the input is not
// already lower-case. Emitting the canonical spelling keeps that fold
// allocation-free on every request that injects a token.
const DefaultTargetHeader = "authorization"

// missingKeySentinel is what text/template writes for an absent map key under
// missingkey=zero. It passes httpguts.ValidHeaderFieldValue, so without an
// explicit check it would reach the upstream as a real header value.
const missingKeySentinel = "<no value>"

type ApiKeyConfig struct {
	Headers []ApiKeyHeaderConfig
}

type ApiKeyHeaderConfig struct {
	Names     []string
	Selector  cel.Program
	Condition *When
	Value     HeaderValueSource
}

type HeaderValueSource struct {
	Literal  *string
	Template *template.Template
	CEL      cel.Program
}

type PreparedApiKeyConfig struct {
	Headers []PreparedHeader
}

type PreparedHeader struct {
	Name          string
	OriginalValue string
	Value         HeaderValueSource
}

type HeaderTemplateData struct {
	Name  string
	Value string
}

// ApiKeyTemplateData is the data visible to value templates. Exported names
// are policy-visible: existing profiles' templates reference them.
type ApiKeyTemplateData struct {
	Token   string
	Header  HeaderTemplateData
	Request inputs.Request
	Pod     inputs.Pod
	Profile inputs.Profile
	Rule    inputs.Rule
	scope   *inputs.Scope
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

// apiKeySigner injects a credential token into configured request headers —
// the OSS default transformation, always registered.
type apiKeySigner struct{}

func (apiKeySigner) Kind() CredentialKind { return CredentialKindToken }

func (apiKeySigner) Prepare(st *filter.Stream, scope *inputs.Scope, cfg any) (any, bool, error) {
	ac, ok := cfg.(ApiKeyConfig)
	if !ok {
		return nil, false, fmt.Errorf("apikey signer: config is %T, want ApiKeyConfig", cfg)
	}
	prepared := make([]PreparedHeader, 0)
	seen := make(map[string]struct{})
	var requestHeaders map[string]string
	if st != nil {
		requestHeaders = st.Request.Headers
	}
	for ruleIndex, header := range ac.Headers {
		if !header.Condition.Met(requestHeaders) {
			continue
		}
		names := header.Names
		if header.Selector != nil {
			if scope == nil {
				return nil, false, fmt.Errorf("apikey signer: evaluate headers[%d] selector: evaluation scope unavailable", ruleIndex)
			}
			var err error
			names, err = evalHeaderSelector(header.Selector, scope.Activation(), maxHeaderTargets-len(seen))
			if err != nil {
				return nil, false, fmt.Errorf("apikey signer: evaluate headers[%d] selector: %w", ruleIndex, err)
			}
		}

		for _, rawName := range names {
			name, err := filter.ValidateHeaderName(filter.HeaderSet, rawName)
			if err != nil {
				return nil, false, fmt.Errorf("apikey signer: headers[%d] target: %w", ruleIndex, err)
			}
			if _, duplicate := seen[name]; duplicate {
				return nil, false, fmt.Errorf("apikey signer: headers[%d] duplicates header %q", ruleIndex, name)
			}
			seen[name] = struct{}{}
			if len(seen) > maxHeaderTargets {
				return nil, false, fmt.Errorf("apikey signer: target list has more than %d headers; want at most %d", maxHeaderTargets, maxHeaderTargets)
			}

			original := ""
			if scope != nil {
				original = scope.Request().Header(name)
			} else if st != nil {
				original = st.Request.Headers[name]
			}
			prepared = append(prepared, PreparedHeader{
				Name: name, OriginalValue: original, Value: header.Value,
			})
		}
	}
	if len(prepared) == 0 {
		return nil, true, nil
	}
	return PreparedApiKeyConfig{Headers: prepared}, false, nil
}

// evalHeaderSelector keeps CEL's typed list representation until its reported
// size is known to fit the target allowance. Only then does it allocate and
// copy the bounded string result used by header validation.
func evalHeaderSelector(prog cel.Program, act cel.Activation, remaining int) ([]string, error) {
	value, _, err := prog.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("eval value: %w", err)
	}
	list, ok := value.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("selector is %T, want list", value.Value())
	}
	size, ok := list.Size().(types.Int)
	if !ok || size < 0 {
		return nil, fmt.Errorf("selector returned invalid list size %v", list.Size())
	}
	if size > types.Int(remaining) {
		return nil, fmt.Errorf("selector returned %d targets, exceeding remaining %d; target list permits at most %d", size, remaining, maxHeaderTargets)
	}

	names := make([]string, 0, int(size))
	for it := list.Iterator(); it.HasNext() == types.True; {
		item := it.Next()
		name, ok := item.(types.String)
		if !ok {
			return nil, fmt.Errorf("selector element %d is %T, want string", len(names), item.Value())
		}
		names = append(names, string(name))
	}
	if len(names) != int(size) {
		return nil, fmt.Errorf("selector reported %d targets but yielded %d", size, len(names))
	}
	return names, nil
}

func renderHeaderValue(source HeaderValueSource, data ApiKeyTemplateData, scope *inputs.Scope) (string, error) {
	switch {
	case source.Literal != nil:
		return *source.Literal, nil
	case source.Template != nil:
		return eval.RenderToString(source.Template, data)
	case source.CEL != nil:
		if scope == nil {
			return "", fmt.Errorf("header value CEL: evaluation scope unavailable")
		}
		top, err := cel.NewActivation(map[string]any{
			"token": data.Token,
			"header": map[string]string{
				"name":  data.Header.Name,
				"value": data.Header.Value,
			},
		})
		if err != nil {
			return "", err
		}
		act := interpreter.NewHierarchicalActivation(scope.Activation(), top)
		value, err := eval.EvalValue(source.CEL, act)
		if err != nil {
			return "", err
		}
		result, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("CEL value is %T, want string", value)
		}
		return result, nil
	default:
		return "", fmt.Errorf("header value source is empty")
	}
}

func (apiKeySigner) Sign(_ context.Context, _ *filter.Stream, _ []byte, scope *inputs.Scope, cred Credential, cfg any) ([]filter.Mutation, error) {
	ac, ok := cfg.(PreparedApiKeyConfig)
	if !ok {
		return nil, fmt.Errorf("apikey signer: config is %T, want PreparedApiKeyConfig", cfg)
	}
	if len(ac.Headers) == 0 {
		return nil, fmt.Errorf("apikey signer: config has no output header")
	}
	// Every output is rendered and validated before any of them is returned,
	// so a value that fails halfway through cannot leave the request with
	// some headers rewritten and others still carrying the caller's own
	// credential. A failure here reaches the caller as an error and resolves
	// through the rule's failStrategy, exactly as a missing credential does.
	ops := make([]filter.HeaderOp, 0, len(ac.Headers))
	for _, header := range ac.Headers {
		data := ApiKeyTemplateData{
			Token:  cred.Token,
			Header: HeaderTemplateData{Name: header.Name, Value: header.OriginalValue},
		}
		if scope != nil {
			data.Request = scope.Request()
			data.Pod = scope.Pod()
			data.Profile = scope.Profile()
			data.Rule = scope.Rule()
			data.scope = scope
		}
		value, err := renderHeaderValue(header.Value, data, scope)
		if err != nil {
			return nil, fmt.Errorf("render header %q: %w", header.Name, err)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("render header %q: value contains invalid characters", header.Name)
		}
		if strings.Contains(value, missingKeySentinel) {
			return nil, fmt.Errorf("render header %q: value resolved to %s", header.Name, missingKeySentinel)
		}
		ops = append(ops, filter.HeaderOp{Kind: filter.HeaderSet, Name: header.Name, Value: value})
	}
	// Only the configured headers are touched. When one of them is
	// Authorization — the default — the set overwrites whatever credential the
	// caller sent. When the config names some other header instead, the
	// caller's Authorization is forwarded alongside the injected value, so an
	// upstream that consults Authorization first may authenticate with the
	// caller's own credential. That is deliberate: stripping it would change
	// behavior for callers that rely on both headers reaching the upstream, so
	// any change belongs behind an explicit policy knob rather than a silent
	// default change.
	return []filter.Mutation{{HeaderOps: ops}}, nil
}
