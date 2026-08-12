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

// Package headermutation applies policy-defined request header changes.
package headermutation

import (
	"context"
	"fmt"
	"text/template"

	"golang.org/x/net/http/httpguts"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// FilterName is the registry name used for policy payloads and attribution.
const FilterName = "headermutation"

// ValueOp is one compiled set or append operation.
type ValueOp struct {
	Name  string
	Value *template.Template
}

// Config is the compiled mutation set for one matched rule.
type Config struct {
	Set    []ValueOp
	Add    []ValueOp
	Remove []string
}

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

// OnRequestHeaders renders every value before returning the mutation set. An
// error therefore cannot expose a partially built action to the engine.
func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	type renderedOp struct {
		kind  filter.HeaderOpKind
		name  string
		value string
	}
	rendered := make([]renderedOp, 0, len(f.cfg.Set)+len(f.cfg.Add))
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
		rendered = append(rendered, renderedOp{kind: kind, name: op.Name, value: value})
		return nil
	}
	for _, op := range f.cfg.Set {
		if err := render(filter.HeaderSet, op); err != nil {
			return filter.Action{}, err
		}
	}
	for _, op := range f.cfg.Add {
		if err := render(filter.HeaderAppend, op); err != nil {
			return filter.Action{}, err
		}
	}

	mutations := make([]filter.Mutation, 0, len(rendered)+len(f.cfg.Remove))
	for _, op := range rendered {
		switch op.kind {
		case filter.HeaderSet:
			mutations = append(mutations, filter.SetHeader(op.name, op.value))
		case filter.HeaderAppend:
			mutations = append(mutations, filter.AppendHeader(op.name, op.value))
		}
	}
	for _, name := range f.cfg.Remove {
		mutations = append(mutations, filter.RemoveHeader(name))
	}
	return filter.Continue(mutations...), nil
}

// Descriptor declares a fail-closed request-headers filter.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders,
		OnError: filter.FailClosed,
		New:     New,
	}
}
