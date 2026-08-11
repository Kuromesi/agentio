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
package filter

import (
	"encoding/json"
	"errors"
	"fmt"

	"istio.io/istio/extensions/epe/pkg/inputs"
)

// FailurePolicy decides what a filter error becomes. Errors never turn
// into gRPC errors; that channel is reserved for adapter/protocol faults.
type FailurePolicy int

const (
	// FailClosed turns the error into a framework-generated deny.
	FailClosed FailurePolicy = iota
	// FailOpen skips this filter and continues.
	FailOpen
	// FromRule consults the policy's declared failure behavior via
	// Descriptor.OnErrorOf. The mapping from CRD FailStrategy to
	// FailurePolicy lives in the filter's own parse, never here.
	FromRule
)

// FailurePolicyOf resolves the failure policy from one projected config.
type FailurePolicyOf[C any] func(cfg C) FailurePolicy

// Descriptor declares one filter to the framework. C is the filter's own
// config type; filter authors never write a type assertion.
type Descriptor[C any] struct {
	Name    string
	Phases  Phase
	Body    BodyNeed
	OnError FailurePolicy
	// OnErrorOf is consulted when OnError == FromRule; nil means FailClosed.
	OnErrorOf FailurePolicyOf[C]
	// New builds one filter invocation from one rule's projected config.
	// Rules are never aggregated: the engine constructs and runs them in
	// policy order.
	New func(RuleConfig[C]) Filter
}

// ErasedRuleConfig is the storage form of RuleConfig inside a Registration.
type ErasedRuleConfig struct {
	ID    UnitID
	Cfg   any
	Scope *inputs.Scope
}

// Registration is the type-erased form stored in an explicitly ordered
// slice — position in the slice is the within-rule action order, which is
// static, written in code, and load-bearing.
type Registration struct {
	Name    string
	Phases  Phase
	Body    BodyNeed
	OnError FailurePolicy
	// Parse turns this filter's payload document into its config. It is
	// only called when the unit carries a payload under this filter's
	// name; "not mine" is the absence of the key, not an error value.
	// Any error means the payload is mine but malformed — fail closed.
	Parse func(raw json.RawMessage) (any, error)
	// New builds the filter from exactly one erased rule config.
	New func(cfg ErasedRuleConfig) Filter
	// PolicyFor resolves FromRule for one erased config.
	PolicyFor func(cfg any) FailurePolicy
}

// Definition owns the typed descriptor and parser until the composition
// root builds the static, type-erased registration sequence.
type Definition struct {
	build func() (Registration, error)
}

// Define binds a typed descriptor to its payload parser. Generics stay on
// the producing side; Build returns the erased registrations consumed by
// policy projection and the request engine.
func Define[C any](d Descriptor[C], parse func(raw json.RawMessage) (C, error)) Definition {
	return Definition{build: func() (Registration, error) {
		return buildRegistration(d, parse)
	}}
}

func buildRegistration[C any](d Descriptor[C], parse func(raw json.RawMessage) (C, error)) (Registration, error) {
	if d.Name == "" {
		return Registration{}, errors.New("filter definition: empty Name")
	}
	if d.New == nil {
		return Registration{}, fmt.Errorf("filter definition %q: nil New", d.Name)
	}
	if parse == nil {
		return Registration{}, fmt.Errorf("filter definition %q: nil parse", d.Name)
	}
	if d.Phases == 0 {
		return Registration{}, fmt.Errorf("filter definition %q: declares no phases", d.Name)
	}
	if undispatched := d.Phases &^ DispatchedPhases; undispatched != 0 {
		return Registration{}, fmt.Errorf("filter definition %q: declares phases %08b the engine does not dispatch; "+
			"widen filter.DispatchedPhases when the engine learns to dispatch them", d.Name, undispatched)
	}
	if d.Body > BodyComplete {
		return Registration{}, fmt.Errorf("filter definition %q: invalid body need %d", d.Name, d.Body)
	}
	hasBodyPhase := d.Phases&PhaseRequestBody != 0
	if hasBodyPhase != (d.Body != BodyNone) {
		return Registration{}, fmt.Errorf("filter definition %q: request-body phase and body need must be declared together", d.Name)
	}
	if hasBodyPhase && d.Phases&PhaseRequestHeaders == 0 {
		return Registration{}, fmt.Errorf("filter definition %q: request-body phase requires request headers", d.Name)
	}
	if d.OnError < FailClosed || d.OnError > FromRule {
		return Registration{}, fmt.Errorf("filter definition %q: invalid failure policy %d", d.Name, d.OnError)
	}
	return Registration{
		Name:    d.Name,
		Phases:  d.Phases,
		Body:    d.Body,
		OnError: d.OnError,
		Parse: func(raw json.RawMessage) (any, error) {
			cfg, err := parse(raw)
			if err != nil {
				return nil, err
			}
			return cfg, nil
		},
		New: func(cfg ErasedRuleConfig) Filter {
			// The assertion cannot fail: the same generic
			// instantiation wrote the value in Parse above.
			return d.New(RuleConfig[C]{ID: cfg.ID, Cfg: cfg.Cfg.(C), Scope: cfg.Scope})
		},
		PolicyFor: func(cfg any) FailurePolicy {
			if d.OnErrorOf == nil {
				return FailClosed
			}
			return d.OnErrorOf(cfg.(C))
		},
	}, nil
}

// Build validates definitions and returns registrations in the exact order
// supplied. That order is the within-rule action order.
func Build(definitions ...Definition) ([]Registration, error) {
	regs := make([]Registration, 0, len(definitions))
	names := make(map[string]struct{}, len(definitions))
	for i, definition := range definitions {
		if definition.build == nil {
			return nil, fmt.Errorf("filter definition %d: zero value", i)
		}
		reg, err := definition.build()
		if err != nil {
			return nil, err
		}
		if _, exists := names[reg.Name]; exists {
			return nil, fmt.Errorf("filter definition %q: duplicate name", reg.Name)
		}
		names[reg.Name] = struct{}{}
		regs = append(regs, reg)
	}
	return regs, nil
}
