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

// spec is symmetric on purpose: both phases take the same opSpec under their
// own key. An earlier draft embedded opSpec so the request operations stayed at
// the top level, but that only bought back-compatibility with a payload shape
// nothing consumes yet — the filter is not wired into the SecurityProfile
// adapter — while permanently making the two phases read as if they differed.
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

// hopByHopResponseNames are rejected on the response phase because Envoy owns
// connection semantics itself (RFC 9110 §7.6.1); content-encoding is rejected
// because we never touch the response body, so changing it misinforms the
// client.
var hopByHopResponseNames = map[string]struct{}{
	"connection":         {},
	"keep-alive":         {},
	"proxy-connection":   {},
	"upgrade":            {},
	"te":                 {},
	"trailer":            {},
	"proxy-authenticate": {},
	"content-encoding":   {},
}

// framingResponseNames may be REMOVEd on the response phase — the codec falls
// back to chunked or connection-close — but never SET or ADDed: Envoy applies
// them blindly at body mode NONE, corrupting HTTP/1 framing.
var framingResponseNames = map[string]struct{}{
	"content-length":    {},
	"transfer-encoding": {},
}

// probeScope is the zero scope every compiled template is rendered against at
// parse time. text/template resolves nothing at parse time, so an unknown
// struct field such as {{ .Response.Status }} would otherwise only fail at
// execute time, once per stream. Unknown fields are type-level and fail
// deterministically here, while missingkey=zero keeps data-dependent probes
// (an absent .Inputs key, an empty pod label) silent — so there are no false
// positives.
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

// headerPhase carries everything phase-dependent about compilation: the
// human-facing message prefix, and whether the response-only name restrictions
// apply.
//
// The two travel together rather than one being derived from the other.
// restrictNames stays an explicit field so that rewording prefix can never
// change which header names are legal; bundling them additionally makes the
// nonsensical combination — a request phase with response restrictions —
// unconstructible at the call sites.
type headerPhase struct {
	prefix        string
	restrictNames bool
}

var (
	requestPhase  = headerPhase{prefix: "request."}
	responsePhase = headerPhase{prefix: "response.", restrictNames: true}
)

// compilePhase validates and compiles one phase's operations. Duplicate
// detection is scoped to the phase: the same header name in the request and in
// the response is legitimate. Within a phase a name may still appear in only
// one of set/add/remove, because Envoy applies all removes before all sets
// inside one HeaderMutation, so `set x-a` plus `remove x-a` reads as "remove
// wins" but actually sets.
func compilePhase(phase headerPhase, s opSpec) (OpSet, error) {
	seen := make(map[string]string, len(s.Set)+len(s.Add)+len(s.Remove))

	validateName := func(kind, name string) (string, error) {
		qualified := phase.prefix + kind
		if !httpguts.ValidHeaderFieldName(name) {
			return "", fmt.Errorf("%s header %q has an invalid name", qualified, name)
		}
		normalized := strings.ToLower(name)
		if normalized == "host" {
			return "", fmt.Errorf("%s header %q cannot modify Host", qualified, name)
		}
		// Bare prefix, deliberately: Envoy gates on
		// absl::StartsWith(name, Http::Headers::get().prefix()) with the default
		// prefix "x-envoy" (mutation_rules.cc:97), so even an unrelated-looking
		// "x-envoyer" is silently ignored by the data plane. Narrowing this to
		// "x-envoy-" would accept such a name here and let it vanish at runtime,
		// which is the exact "configured but inert" failure this check prevents.
		if strings.HasPrefix(normalized, "x-envoy") {
			return "", fmt.Errorf("%s header %q is reserved by Envoy and would be ignored", qualified, name)
		}
		if phase.restrictNames {
			if _, forbidden := hopByHopResponseNames[normalized]; forbidden {
				return "", fmt.Errorf("%s header %q is connection-scoped and cannot be mutated", qualified, name)
			}
			if _, framing := framingResponseNames[normalized]; framing && kind != "remove" {
				return "", fmt.Errorf("%s header %q controls response framing and can only be removed", qualified, name)
			}
		}
		if previous, exists := seen[normalized]; exists {
			return "", fmt.Errorf("%s header %q duplicates %s%s header %q", qualified, name, phase.prefix, previous, normalized)
		}
		seen[normalized] = kind
		return normalized, nil
	}

	compile := func(kind string, ops []valueSpec) ([]ValueOp, error) {
		qualified := phase.prefix + kind
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
