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
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// --- test filters ------------------------------------------------------

type counters struct {
	constructed int
	headerCalls int
	bodyCalls   int
}

type actionFilter struct {
	filter.PassThrough
	act filter.Action
	c   *counters
}

func (f *actionFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return f.act, nil
}

type mutatingFilter struct {
	filter.PassThrough
	c    *counters
	muts []filter.Mutation
	// seen collects the unit names this instance was constructed with.
	seen []string
}

func (f *mutatingFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return filter.Continue(f.muts...), nil
}

type bodyFilter struct {
	filter.PassThrough
	c       *counters
	bodyAct filter.Action
}

func (f *bodyFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return filter.NeedBody(), nil
}

func (f *bodyFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	f.c.bodyCalls++
	return f.bodyAct, nil
}

type errFilter struct {
	filter.PassThrough
	err error
}

func (f *errFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(), f.err
}

// --- registration helpers ----------------------------------------------

type regSpec struct {
	name     string
	onError  filter.FailurePolicy
	policyOf func(cfg string) filter.FailurePolicy
	make     func(cfg filter.RuleConfig[string]) filter.Filter
	// phases overrides the default request-headers|request-body mask.
	phases filter.Phase
}

func buildRegs(t testing.TB, specs []regSpec) []filter.Registration {
	t.Helper()
	definitions := make([]filter.Definition, 0, len(specs))
	for _, sp := range specs {
		phases := sp.phases
		if phases == 0 {
			phases = filter.PhaseRequestHeaders | filter.PhaseRequestBody
		}
		body := filter.BodyNone
		if phases&filter.PhaseRequestBody != 0 {
			body = filter.BodyComplete
		}
		d := filter.Descriptor[string]{
			Name:      sp.name,
			Phases:    phases,
			Body:      body,
			OnError:   sp.onError,
			OnErrorOf: sp.policyOf,
			New:       sp.make,
		}
		// Parse is never invoked: engine tests build units with pre-parsed
		// configs (unitsFor), so the JSON seam stays a stub.
		definitions = append(definitions, filter.Define(d, func(json.RawMessage) (string, error) {
			return "", nil
		}))
	}
	regs, err := filter.Build(definitions...)
	if err != nil {
		t.Fatalf("build registrations: %v", err)
	}
	return regs
}

// unitsFor builds units where cfgRow[i][j] is the config for unit i /
// registration j; "" means the unit doesn't carry that filter's config.
func unitsFor(cfgRows [][]string) []Unit {
	units := make([]Unit, len(cfgRows))
	for i, row := range cfgRows {
		cfgs := make([]any, len(row))
		for j, v := range row {
			if v != "" {
				cfgs[j] = v
			}
		}
		units[i] = Unit{
			ID:   filter.UnitID{Scope: "ns/p", Name: "r" + strconv.Itoa(i), Ordinal: i},
			Cfgs: cfgs,
		}
	}
	return units
}

func requireDisposition(t *testing.T, got, want Disposition) {
	t.Helper()
	if got != want {
		t.Fatalf("Disposition = %v, want %v", got, want)
	}
}

func TestEngineCopiesRegistrations(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name: "original",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filter.PassThrough{}
		},
	}})
	e := NewEngine(regs, 0)
	regs[0].Name = "caller-mutated"
	got := e.Registrations()
	if got[0].Name != "original" {
		t.Fatalf("engine retained caller slice: %#v", got)
	}
	got[0].Name = "accessor-mutated"
	if e.Registrations()[0].Name != "original" {
		t.Fatal("Registrations exposed engine storage")
	}
}

func TestEvalRejectsMisalignedUnitConfigs(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name: "one",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filter.PassThrough{}
		},
	}})
	e := NewEngine(regs, 0)
	_, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, []Unit{{
		ID:   filter.UnitID{Scope: "ns/p", Name: "r"},
		Cfgs: nil,
	}})
	if err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("misaligned configs error = %v", err)
	}
}

func TestEval_StrictRuleOrderRunsEarlierWorkBeforeLaterBlock(t *testing.T) {
	earlier := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "earlier", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: earlier, muts: []filter.Mutation{filter.SetHeader("x-earlier", "1")}}
		}},
		{name: "block", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Stop(filter.Reply{Status: 403}), c: &counters{}}
		}},
	})

	res, err := NewEngine(regs, 0).EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{
		{"run", ""},
		{"", "block"},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBlocked)
	if earlier.headerCalls != 1 {
		t.Fatalf("earlier rule ran %d times, want 1 before the later block", earlier.headerCalls)
	}
}

func TestEval_BypassStopsOnlyFollowingRules(t *testing.T) {
	earlier := &counters{}
	later := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "body", make: func(cfg filter.RuleConfig[string]) filter.Filter {
			if cfg.Cfg == "earlier" {
				return &bodyFilter{c: earlier, bodyAct: filter.Continue()}
			}
			return &bodyFilter{c: later, bodyAct: filter.Continue()}
		}},
		{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Bypass(), c: &counters{}}
		}},
	})

	res, err := NewEngine(regs, 0).EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{
		{"earlier", ""},
		{"", "bypass"},
		{"later", ""},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if !res.NeedsBody() {
		t.Fatal("NeedsBody = false, want the earlier rule to pause before bypass is reached")
	}
	if earlier.headerCalls != 1 || later.headerCalls != 0 {
		t.Fatalf("header calls: earlier=%d later=%d, want 1 and 0", earlier.headerCalls, later.headerCalls)
	}
}

// --- the verification table -------------------------------------------

func TestEval_OrderedRulesTable(t *testing.T) {
	ctx := context.Background()
	st := &filter.Stream{}

	// Bespoke action order used to exercise each action kind.
	newChain := func() (regs []filter.Registration, bypassC, blockC, mcpC, ttC *counters) {
		bypassC, blockC, mcpC, ttC = &counters{}, &counters{}, &counters{}, &counters{}
		regs = buildRegs(t, []regSpec{
			{name: "bypass", make: func(c filter.RuleConfig[string]) filter.Filter {
				bypassC.constructed++
				return &actionFilter{act: filter.Bypass(), c: bypassC}
			}},
			{name: "mcp", make: func(c filter.RuleConfig[string]) filter.Filter {
				mcpC.constructed++
				return &bodyFilter{c: mcpC, bodyAct: filter.Continue()}
			}},
			{name: "block", make: func(c filter.RuleConfig[string]) filter.Filter {
				blockC.constructed++
				return &actionFilter{act: filter.Stop(filter.Reply{Status: 451}), c: blockC}
			}},
			{name: "tt", make: func(c filter.RuleConfig[string]) filter.Filter {
				ttC.constructed++
				f := &mutatingFilter{c: ttC, muts: []filter.Mutation{filter.SetHeader("x-token", "1")}}
				f.seen = append(f.seen, c.ID.Name)
				return f
			}},
		})
		return
	}
	// column order: bypass, mcp, block, tt
	t.Run("block rule then bypass rule -> blocked and remaining actions skipped", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "b", "t"},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBlocked)
		if res.Reply.Status != 451 {
			t.Errorf("Reply.Status = %d, want 451", res.Reply.Status)
		}
		if ttC.constructed != 0 {
			t.Errorf("mutation filter constructed %d times; block must skip remaining work", ttC.constructed)
		}
	})

	t.Run("same unit bypass+block -> bypassed (action order in unit)", func(t *testing.T) {
		regs, _, blockC, _, _ := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"y", "", "b", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if blockC.headerCalls != 0 {
			t.Errorf("block ran %d times; bypass precedes it in action order", blockC.headerCalls)
		}
	})

	t.Run("tt rule then bypass rule -> mutation preserved", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "", "t"},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if ttC.headerCalls != 1 {
			t.Errorf("tt ran %d times, want 1", ttC.headerCalls)
		}
		if len(res.HeaderOps) != 1 || res.HeaderOps[0].Name != "x-token" {
			t.Errorf("HeaderOps = %+v, want preserved x-token", res.HeaderOps)
		}
	})

	t.Run("bypass rule then tt rule -> no injection", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"y", "", "", ""},
			{"", "", "", "t"},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if ttC.constructed != 0 {
			t.Errorf("tt constructed %d times; its unit is after the stopping action", ttC.constructed)
		}
		if len(res.HeaderOps) != 0 {
			t.Errorf("HeaderOps = %+v, want none", res.HeaderOps)
		}
	})

	t.Run("mcp rule then bypass rule -> body work completes before bypass", func(t *testing.T) {
		regs, _, _, mcpC, _ := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "m", "", ""},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionPassthrough)
		if mcpC.headerCalls != 1 {
			t.Errorf("earlier body filter ran %d times, want 1", mcpC.headerCalls)
		}
		if !res.NeedsBody() {
			t.Fatal("NeedsBody = false; the earlier rule must complete before bypass")
		}
		bodyRes, err := e.EvalRequestBody(ctx, st, res, filter.Body{Complete: true})
		if err != nil {
			t.Fatalf("EvalRequestBody: %v", err)
		}
		requireDisposition(t, bodyRes.Disposition, DispositionBypassed)
		if mcpC.bodyCalls != 1 {
			t.Errorf("earlier body filter finalized %d times, want 1", mcpC.bodyCalls)
		}
	})

	t.Run("tt rule then block rule -> earlier work runs before block", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "", "t"},
			{"", "", "b", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBlocked)
		if ttC.constructed != 1 {
			t.Errorf("tt constructed %d times, want 1 before later block", ttC.constructed)
		}
	})
}

func TestEval_NewNeverCalledWithEmptyConfigs(t *testing.T) {
	var newCalls []int
	regs := buildRegs(t, []regSpec{
		{name: "m", make: func(filter.RuleConfig[string]) filter.Filter {
			newCalls = append(newCalls, 1)
			return &mutatingFilter{c: &counters{}}
		}},
	})
	e := NewEngine(regs, 0)
	// No unit carries m's config.
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{""}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	for _, n := range newCalls {
		if n == 0 {
			t.Fatal("New called with empty config slice")
		}
	}
	if len(newCalls) != 0 {
		t.Fatalf("New called %d times, want 0", len(newCalls))
	}
}

func TestEval_EachRuleConfigRunsOnce(t *testing.T) {
	c := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "action", make: func(filter.RuleConfig[string]) filter.Filter {
			c.constructed++
			return &actionFilter{act: filter.Continue(), c: c}
		}},
	})
	e := NewEngine(regs, 0)
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}, {"b"}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if c.headerCalls != 2 {
		t.Fatalf("filter ran %d times, want once for each of 2 rules", c.headerCalls)
	}
}

func TestEval_FilterRunsOncePerConfiguredUnit(t *testing.T) {
	var got []string
	regs := buildRegs(t, []regSpec{
		{name: "m", make: func(c filter.RuleConfig[string]) filter.Filter {
			f := &mutatingFilter{c: &counters{}}
			got = append(got, c.Cfg)
			return f
		}},
	})
	e := NewEngine(regs, 0)
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}, {""}, {"c"}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("configs = %v, want [a c]", got)
	}
}

func TestEvalBody_StopShortCircuits(t *testing.T) {
	stopC, contC := &counters{}, &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "deny", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: stopC, bodyAct: filter.Stop(filter.Reply{Status: 452})}
		}},
		{name: "later", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: contC, bodyAct: filter.Continue()}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"d", "l"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !hr.NeedsBody() {
		t.Fatal("NeedsBody = false, want true")
	}
	br, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Bytes: []byte("{}"), Complete: true})
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBlocked)
	if br.Reply.Status != 452 {
		t.Errorf("Reply.Status = %d, want 452", br.Reply.Status)
	}
	if contC.bodyCalls != 0 {
		t.Errorf("later body filter ran %d times after a Stop", contC.bodyCalls)
	}
}

func TestEvalBody_LaterBypassPreservesEarlierMutationAndSkipsFollowingRule(t *testing.T) {
	earlier := &counters{}
	later := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "body", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: earlier, bodyAct: filter.Continue(filter.SetHeader("x-body", "1"))}
		}},
		{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Bypass(), c: &counters{}}
		}},
		{name: "later", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: later, muts: []filter.Mutation{filter.SetHeader("x-later", "1")}}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{
		{"body", "", ""},
		{"", "bypass", ""},
		{"", "", "later"},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	br, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBypassed)
	if len(br.HeaderOps) != 1 || br.HeaderOps[0].Name != "x-body" {
		t.Fatalf("HeaderOps = %+v, want preserved earlier body mutation", br.HeaderOps)
	}
	if later.headerCalls != 0 {
		t.Fatalf("following rule ran %d times after bypass", later.headerCalls)
	}
}

func TestEvalBody_NeedRejected(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "greedy", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: &counters{}, bodyAct: filter.NeedBody()}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"g"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if _, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Complete: true}); err == nil {
		t.Fatal("want error: Need from the body phase would be silently ignored by Envoy")
	}
}

func TestInvoke_FailOpenSkips(t *testing.T) {
	mutC := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "flaky", onError: filter.FailOpen, make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
		{name: "after", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: mutC, muts: []filter.Mutation{filter.SetHeader("x", "1")}}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"f", "a"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionMutated)
	if mutC.headerCalls != 1 {
		t.Errorf("later filter ran %d times, want 1 — fail-open must not stop the chain", mutC.headerCalls)
	}
	foundOpen := false
	for _, u := range st.Info.Matched {
		for _, a := range u.FilterActions {
			if a == "flaky:error-open" {
				foundOpen = true
			}
		}
	}
	if !foundOpen {
		t.Error("no error-open record for the failing filter")
	}
}

func TestInvoke_FailClosedErrors(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "strict", onError: filter.FailClosed, make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
	})
	e := NewEngine(regs, 0)
	res, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"s"}}))
	if err == nil {
		t.Fatal("want error from fail-closed filter")
	}
	requireDisposition(t, res.Disposition, DispositionError)
}

func TestInvoke_FromRuleConsultsPolicy(t *testing.T) {
	mk := func(filter.RuleConfig[string]) filter.Filter { return &errFilter{err: errors.New("boom")} }
	policy := func(cfg string) filter.FailurePolicy {
		if cfg == "open" {
			return filter.FailOpen
		}
		return filter.FailClosed
	}
	regs := buildRegs(t, []regSpec{{name: "fr", onError: filter.FromRule, policyOf: policy, make: mk}})
	e := NewEngine(regs, 0)

	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"open"}})); err != nil {
		t.Fatalf("open policy: Eval err = %v, want fail-open", err)
	}
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"closed"}})); err == nil {
		t.Fatal("closed policy: want error")
	}
}

// bodyErrFilter asks for the body on headers, then fails in the body phase.
type bodyErrFilter struct {
	filter.PassThrough
	err error
}

func (f *bodyErrFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func (f *bodyErrFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), f.err
}

// A FromRule filter that fails in the body phase must consult its config's
// policy, exactly as the headers phase does: a nil cfg would fall back to
// FailClosed and block a rule declaring failStrategy: Allow. tokentransform
// is the only FromRule filter in the tree and it is body-phase.
func TestEvalBody_FromRuleConsultsPolicy(t *testing.T) {
	mk := func(filter.RuleConfig[string]) filter.Filter {
		return &bodyErrFilter{err: errors.New("boom")}
	}
	policy := func(cfg string) filter.FailurePolicy {
		if cfg == "open" {
			return filter.FailOpen
		}
		return filter.FailClosed
	}
	regs := buildRegs(t, []regSpec{{
		name: "fr-body", onError: filter.FromRule, policyOf: policy, make: mk,
	}})
	e := NewEngine(regs, 0)

	run := func(cfg string) error {
		st := &filter.Stream{}
		res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{cfg}}))
		if err != nil {
			t.Fatalf("headers phase erred unexpectedly: %v", err)
		}
		if !res.NeedsBody() {
			t.Fatal("filter did not request the body")
		}
		_, err = e.EvalRequestBody(context.Background(), st, res, filter.Body{Bytes: []byte("x"), Complete: true})
		return err
	}

	if err := run("open"); err != nil {
		t.Errorf("FailOpen policy: EvalRequestBody err = %v, want fail-open (nil)", err)
	}
	if err := run("closed"); err == nil {
		t.Error("FailClosed policy: want an error")
	}
}

// respMutFilter declares the response-headers phase and returns a mutation.
type respMutFilter struct {
	filter.PassThrough
}

func (respMutFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(filter.SetHeader("x-resp", "v")), nil
}

// TestEvalResponseHeaders pins the response-phase contract: the entry point
// only returns an error — there is nowhere for mutations to go — so a filter
// returning response-phase mutations must surface as an error naming the
// filter instead of being silently dropped, while an observation-only filter
// (no mutations) stays legal because observation is the supported use.
func TestEvalResponseHeaders(t *testing.T) {
	tests := []struct {
		name string
		make func(filter.RuleConfig[string]) filter.Filter
		// wantErrContaining non-empty means an error naming the offending
		// filter is required; empty means the call must succeed.
		wantErrContaining string
	}{
		{
			name:              "mutations are not silently dropped",
			make:              func(filter.RuleConfig[string]) filter.Filter { return respMutFilter{} },
			wantErrContaining: "resp",
		},
		{
			name: "observation-only is fine",
			make: func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			regs := buildRegs(t, []regSpec{{
				name:   "resp",
				phases: filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
				make:   tc.make,
			}})
			e := NewEngine(regs, 0)

			err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}))
			if tc.wantErrContaining == "" {
				if err != nil {
					t.Fatalf("observation-only response filter erred: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("response-phase mutations were dropped without an error")
			}
			if !strings.Contains(err.Error(), tc.wantErrContaining) {
				t.Errorf("err = %v, want it to name the offending filter", err)
			}
		})
	}
}

func TestEval_BypassDoesNotInvokeOrRecordFollowingBlock(t *testing.T) {
	regs, _, _, _, _ := func() ([]filter.Registration, *counters, *counters, *counters, *counters) {
		bypassC, blockC := &counters{}, &counters{}
		regs := buildRegs(t, []regSpec{
			{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
				bypassC.constructed++
				return &actionFilter{act: filter.Bypass(), c: bypassC}
			}},
			{name: "block", make: func(filter.RuleConfig[string]) filter.Filter {
				blockC.constructed++
				return &actionFilter{act: filter.Stop(filter.Reply{Status: 451}), c: blockC}
			}},
		})
		return regs, bypassC, blockC, nil, nil
	}()
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	// unit 0: bypass; unit 1: block (skipped, never evaluated)
	if _, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{
		{"y", ""},
		{"", "b"},
	})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if st.Info.Disposition != DispositionBypassed {
		t.Fatalf("Disposition = %v, want Bypassed", st.Info.Disposition)
	}
	var blockSeen, winner bool
	for _, u := range st.Info.Matched {
		for _, a := range u.FilterActions {
			if strings.HasPrefix(a, "block:") {
				blockSeen = true
			}
			if a == "bypass:bypass" {
				winner = true
			}
		}
	}
	if !winner || blockSeen {
		t.Errorf("Matched = %+v; want bypass recorded and following block absent", st.Info.Matched)
	}
}

// Every invocation lands in StreamInfo.Filters — including a fail-open
// error, whose Err must survive the swallow.
func TestEval_FilterRecordsIncludeFailOpenErr(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "flaky", onError: filter.FailOpen, make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	if _, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"f"}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(st.Info.Filters) != 1 {
		t.Fatalf("Filters = %d records, want 1", len(st.Info.Filters))
	}
	rec := st.Info.Filters[0]
	if rec.Filter != "flaky" || rec.Outcome != "error" || rec.Err == nil {
		t.Errorf("record = %+v; the swallowed error must be visible", rec)
	}
	if st.Info.Disposition != DispositionPassthrough {
		t.Errorf("Disposition = %v; fail-open must not fail the stream", st.Info.Disposition)
	}
}

// The declared BodyNeed drives mode negotiation; a NeedBody from a filter
// that declared BodyNone would silently default a mode, so it is rejected
// as a programming error — that keeps Descriptor.Body load-bearing.
func TestDefinition_RequestBodyContractRejected(t *testing.T) {
	_, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   "undeclared",
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Body:   filter.BodyNone,
		New: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: &counters{}, bodyAct: filter.Continue()}
		},
	}, func(json.RawMessage) (string, error) { return "", nil }))
	if err == nil {
		t.Fatal("want definition error: request-body phase without a body need")
	}
}

// The paused filter's declared complete-body need drives mode negotiation.
func TestEval_BodyNeedMatchesPausedFilter(t *testing.T) {
	mk := func(name string) filter.Registration {
		regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
			Name:   name,
			Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
			Body:   filter.BodyComplete,
			New: func(filter.RuleConfig[string]) filter.Filter {
				return &bodyFilter{c: &counters{}, bodyAct: filter.Continue()}
			},
		}, func(json.RawMessage) (string, error) { return "", nil }))
		if err != nil {
			t.Fatalf("build %s: %v", name, err)
		}
		return regs[0]
	}
	e := NewEngine([]filter.Registration{mk("complete")}, 0)
	res, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !res.NeedsBody() || res.BodyNeed != filter.BodyComplete {
		t.Fatalf("BodyNeed = %v needsBody=%v, want BodyComplete", res.BodyNeed, res.NeedsBody())
	}
}
