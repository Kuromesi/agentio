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

// Package headermutation applies policy-defined request and response header
// changes. Response templates use request-time scope and cannot access response data.
package headermutation

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	"golang.org/x/net/http/httpguts"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// FilterName is the registry name used for policy payloads and attribution.
const FilterName = "headermutation"

// ValueOp is one compiled set or add operation.
type ValueOp struct {
	Name  string
	Value *template.Template
}

// OpSet is the compiled mutation set for one phase.
type OpSet struct {
	Set    []ValueOp
	Add    []ValueOp
	Remove []string
}

// empty reports whether this phase carries no operations at all. An empty
// `response: {}` object therefore counts as zero response operations rather
// than as "the response phase is requested".
func (o OpSet) empty() bool { return len(o.Set)+len(o.Add)+len(o.Remove) == 0 }

// Config contains compiled mutations for each header phase.
type Config struct {
	Request  OpSet
	Response OpSet
}

// HasResponseOps reports whether response-header mutations are configured.
func (c Config) HasResponseOps() bool { return !c.Response.empty() }

// Filter applies one rule's compiled header mutations.
type Filter struct {
	filter.PassThrough
	cfg   Config
	scope *inputs.Scope
}

// New builds a filter invocation for one rule.
func New(rule filter.RuleConfig[Config]) filter.Filter {
	return &Filter{cfg: rule.Cfg, scope: rule.Scope}
}

// missingKeySentinel is what text/template writes for an absent map key under
// missingkey=zero. It passes httpguts.ValidHeaderFieldValue, so without an
// explicit check it would reach the wire as a real header value.
const missingKeySentinel = "<no value>"

// OnRequestHeaders renders configured request-header mutations.
func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	mutations, err := f.mutationsFor(f.cfg.Request)
	if err != nil {
		return filter.Action{}, err
	}
	return filter.Continue(mutations...), nil
}

// OnResponseHeaders renders configured response-header mutations.
func (f *Filter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	mutations, err := f.mutationsFor(f.cfg.Response)
	if err != nil {
		return filter.Action{}, err
	}
	return filter.Continue(mutations...), nil
}

// mutationsFor renders every value before building any mutation, so a render
// error can never surface a partially built mutation set to the engine.
func (f *Filter) mutationsFor(ops OpSet) ([]filter.Mutation, error) {
	type renderedOp struct {
		kind  filter.HeaderOpKind
		name  string
		value string
	}
	rendered := make([]renderedOp, 0, len(ops.Set)+len(ops.Add))
	render := func(kind filter.HeaderOpKind, op ValueOp) error {
		if op.Value == nil {
			return fmt.Errorf("render header %q: nil value template", op.Name)
		}
		value, err := eval.RenderToString(op.Value, f.scope)
		if err != nil {
			return fmt.Errorf("render header %q: %w", op.Name, err)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("render header %q: value contains invalid characters", op.Name)
		}
		if strings.Contains(value, missingKeySentinel) {
			return fmt.Errorf("render header %q: value resolved to %s", op.Name, missingKeySentinel)
		}
		rendered = append(rendered, renderedOp{kind: kind, name: op.Name, value: value})
		return nil
	}
	for _, op := range ops.Set {
		if err := render(filter.HeaderSet, op); err != nil {
			return nil, err
		}
	}
	for _, op := range ops.Add {
		if err := render(filter.HeaderAdd, op); err != nil {
			return nil, err
		}
	}

	mutations := make([]filter.Mutation, 0, len(rendered)+len(ops.Remove))
	for _, op := range rendered {
		switch op.kind {
		case filter.HeaderSet:
			mutations = append(mutations, filter.SetHeader(op.name, op.value))
		case filter.HeaderAdd:
			mutations = append(mutations, filter.AddHeader(op.name, op.value))
		}
	}
	for _, name := range ops.Remove {
		mutations = append(mutations, filter.RemoveHeader(name))
	}
	return mutations, nil
}

// Descriptor declares a fail-closed filter for request and response headers.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
		OnError: filter.Always[Config](filter.FailClosed),
		SubscribesOf: func(c Config) filter.Phase {
			if !c.HasResponseOps() {
				return 0
			}
			return filter.PhaseResponseHeaders
		},
		New: New,
	}
}
