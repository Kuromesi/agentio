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
)

// FailurePolicyOf resolves the failure policy from one projected config.
type FailurePolicyOf[C any] func(cfg C) FailurePolicy

// Always returns a FailurePolicyOf that reports p regardless of config, for
// filters whose failure policy is static.
func Always[C any](p FailurePolicy) FailurePolicyOf[C] {
	return func(C) FailurePolicy { return p }
}

// Descriptor declares one filter to the framework. C is the filter's own
// config type; filter authors never write a type assertion.
type Descriptor[C any] struct {
	Name   string
	Phases Phase
	// OnError resolves the failure policy from one projected config. nil
	// means FailClosed. The mapping from CRD FailStrategy to FailurePolicy
	// lives in the filter's own parse, never here.
	OnError FailurePolicyOf[C]
	// SubscribesOf reports which phases this config needs Envoy to deliver, as
	// opposed to Phases, which reports where the filter is merely able to run.
	// nil means "only the phases that arrive unconditionally".
	//
	// It takes the compiled config and nothing else — deliberately no Stream, no
	// context, no dependencies. Subscription must be settled before the ordered
	// walk begins, because Envoy honours mode_override only on a header-phase reply
	// and the walk may suspend mid-sequence waiting for a body; a want discovered by
	// running a filter can therefore arrive after the request-headers reply was
	// already sent. Handing this function no capabilities is also what makes it
	// side-effect-free structurally rather than by convention.
	//
	// Only the response-headers phase needs this. Request headers arrive
	// unconditionally, so nothing subscribes to them. The request body is
	// subscribed at runtime instead, via a NeedBody action, and that asymmetry is
	// deliberate rather than historical: a body want discovered late is still
	// satisfiable, because once any rule has asked, the body is in hand and the
	// engine satisfies a later NeedBody inline. Response headers have no such
	// recovery — response_header_mode is only useful on the request-headers reply, so
	// once that reply is out the phase can no longer be opened. Do not "unify" the
	// two: moving the body want here would mean buffering speculatively on every
	// request whose config merely might need it, and would strand the failure
	// policy that a runtime body decision can route an error through
	// (see tokentransform's failEligible path).
	//
	// Do not generalise "one shot" from this. The response-headers reply is itself a
	// header-phase reply and can carry an override, which is how a response *body*
	// want would stay recoverable. See engine.SubscribablePhases.
	SubscribesOf func(cfg C) Phase
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
	Name   string
	Phases Phase
	// OnError resolves the failure policy for one erased config. Always
	// non-nil after Build; returns FailClosed when the filter declared no
	// policy or cfg is nil.
	OnError func(cfg any) FailurePolicy
	// Parse turns this filter's payload document into its config. It is
	// only called when the unit carries a payload under this filter's
	// name; "not mine" is the absence of the key, not an error value.
	// Any error means the payload is mine but malformed — fail closed.
	Parse func(raw json.RawMessage) (any, error)
	// New builds the filter from exactly one erased rule config.
	New func(cfg ErasedRuleConfig) Filter
	// Subscribes reports, for one erased config, which phases Envoy must be
	// asked to deliver. Always non-nil after Build; returns 0 when the filter
	// declared no SubscribesOf. Already intersected with Phases.
	Subscribes func(cfg any) Phase
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
	if d.Phases&PhaseRequestBody != 0 && d.Phases&PhaseRequestHeaders == 0 {
		return Registration{}, fmt.Errorf("filter definition %q: request-body phase requires request headers", d.Name)
	}
	return Registration{
		Name:   d.Name,
		Phases: d.Phases,
		OnError: func(cfg any) FailurePolicy {
			if cfg == nil || d.OnError == nil {
				return FailClosed
			}
			return d.OnError(cfg.(C))
		},
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
		Subscribes: func(cfg any) Phase {
			if d.SubscribesOf == nil {
				return 0
			}
			// Narrowed to declared capability: subscribing to a phase the
			// filter cannot run in would open an Envoy round trip that
			// dispatches to nobody. Silently narrowing rather than erroring
			// keeps this a pure function; Build already rejects a Phases mask
			// outside DispatchedPhases, so the intersection is meaningful.
			return d.SubscribesOf(cfg.(C)) & d.Phases
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
