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

package headermutation

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// spec uses the same operation shape for request and response headers.
type spec struct {
	Request  opSpec `json:"request,omitempty"`
	Response opSpec `json:"response,omitempty"`
}

type opSpec struct {
	Set    []valueSpec `json:"set,omitempty"`
	Add    []valueSpec `json:"add,omitempty"`
	Remove []string    `json:"remove,omitempty"`
}

func (o opSpec) empty() bool { return len(o.Set)+len(o.Add)+len(o.Remove) == 0 }

type valueSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// hopByHopNames are rejected on both phases because Envoy owns connection
// semantics itself (RFC 9110 §7.6.1); content-encoding is rejected because this
// filter never touches a body, so changing it misinforms the recipient.
var hopByHopNames = map[string]struct{}{
	"connection":         {},
	"keep-alive":         {},
	"proxy-connection":   {},
	"upgrade":            {},
	"te":                 {},
	"trailer":            {},
	"proxy-authenticate": {},
	"content-encoding":   {},
}

// framingNames may be removed but not set or added because mutations run
// without body updates and could corrupt HTTP/1 framing.
var framingNames = map[string]struct{}{
	"content-length":    {},
	"transfer-encoding": {},
}

// probeScope validates template field access during compilation while allowing
// missing dynamic map keys.
func probeScope() *inputs.Scope {
	return inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil)
}

func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	if s.Request.empty() && s.Response.empty() {
		return Config{}, fmt.Errorf("header mutation has no operations")
	}

	request, err := compilePhase(requestPhase, s.Request)
	if err != nil {
		return Config{}, err
	}
	response, err := compilePhase(responsePhase, s.Response)
	if err != nil {
		return Config{}, err
	}
	return Config{Request: request, Response: response}, nil
}

// Phase prefixes qualify error messages; the name restrictions themselves are
// identical on both phases — see hopByHopNames and framingNames.
const (
	requestPhase  = "request."
	responsePhase = "response."
)

// compilePhase validates and compiles one phase. A header name may appear in
// only one operation kind within that phase.
func compilePhase(prefix string, s opSpec) (OpSet, error) {
	seen := make(map[string]string, len(s.Set)+len(s.Add)+len(s.Remove))

	validateName := func(kind, name string) (string, error) {
		qualified := prefix + kind
		if !httpguts.ValidHeaderFieldName(name) {
			return "", fmt.Errorf("%s header %q has an invalid name", qualified, name)
		}
		normalized := strings.ToLower(name)
		if normalized == "host" {
			return "", fmt.Errorf("%s header %q cannot modify Host", qualified, name)
		}
		// Envoy ignores all names with the reserved "x-envoy" prefix.
		if strings.HasPrefix(normalized, "x-envoy") {
			return "", fmt.Errorf("%s header %q is reserved by Envoy and would be ignored", qualified, name)
		}
		if _, forbidden := hopByHopNames[normalized]; forbidden {
			return "", fmt.Errorf("%s header %q is connection-scoped and cannot be mutated", qualified, name)
		}
		if _, framing := framingNames[normalized]; framing && kind != "remove" {
			return "", fmt.Errorf("%s header %q controls message framing and can only be removed", qualified, name)
		}
		if previous, exists := seen[normalized]; exists {
			return "", fmt.Errorf("%s header %q duplicates %s%s header %q", qualified, name, prefix, previous, normalized)
		}
		seen[normalized] = kind
		return normalized, nil
	}

	compile := func(kind string, ops []valueSpec) ([]ValueOp, error) {
		qualified := prefix + kind
		out := make([]ValueOp, 0, len(ops))
		for _, op := range ops {
			name, err := validateName(kind, op.Name)
			if err != nil {
				return nil, err
			}
			tmpl, err := eval.CompileTemplate(qualified+" header "+op.Name, op.Value)
			if err != nil {
				return nil, fmt.Errorf("compile %s header %q: %w", qualified, op.Name, err)
			}
			if _, err := eval.RenderToString(tmpl, probeScope()); err != nil {
				return nil, fmt.Errorf("compile %s header %q: %w", qualified, op.Name, err)
			}
			out = append(out, ValueOp{Name: name, Value: tmpl})
		}
		return out, nil
	}

	set, err := compile("set", s.Set)
	if err != nil {
		return OpSet{}, err
	}
	add, err := compile("add", s.Add)
	if err != nil {
		return OpSet{}, err
	}
	remove := make([]string, len(s.Remove))
	for i, name := range s.Remove {
		normalized, err := validateName("remove", name)
		if err != nil {
			return OpSet{}, err
		}
		remove[i] = normalized
	}
	return OpSet{Set: set, Add: add, Remove: remove}, nil
}

// Definition binds the payload parser to the typed filter descriptor.
func Definition() filter.Definition { return filter.Define(Descriptor(), parse) }
