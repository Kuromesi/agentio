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
	"fmt"
	"time"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// Disposition aliases the filter-level type; the engine derives it from
// which Action constructor won.
type Disposition = filter.Disposition

const (
	DispositionPassthrough = filter.DispositionPassthrough
	DispositionMutated     = filter.DispositionMutated
	DispositionBlocked     = filter.DispositionBlocked
	DispositionBypassed    = filter.DispositionBypassed
	DispositionError       = filter.DispositionError
)

// Unit action kinds recorded into StreamInfo.
const (
	ActionBlock     = "block"
	ActionBypass    = "bypass"
	ActionMutate    = "mutate"
	ActionNeedBody  = "need-body"
	ActionErrorOpen = "error-open"
)

// Unit is the engine-facing view of one matched policy unit: identity,
// evaluation scope, and the per-registration projected configs. A policy
// resolver may carry richer attribution alongside it; the engine never sees
// the policy model.
type Unit struct {
	ID    filter.UnitID
	Scope *inputs.Scope
	// Cfgs[i] is the projected config for registration i; nil when the
	// unit does not carry that filter's config.
	Cfgs []any
}

// Engine evaluates rules in policy order and actions in registration order.
// It records every invocation and unit action into Stream.Info when the
// caller attached one.
type Engine struct {
	regs   []filter.Registration
	budget time.Duration
	// metrics is parallel to regs: metrics[i] holds registration i's
	// pre-resolved Prometheus children for every dispatched phase.
	metrics []regMetrics
}

// NewEngine builds an engine. budget bounds each evaluation phase (one
// ext_proc message); zero disables the bound.
func NewEngine(regs []filter.Registration, budget time.Duration) *Engine {
	frozen := append([]filter.Registration(nil), regs...)
	return &Engine{regs: frozen, budget: budget, metrics: buildMetrics(frozen)}
}

// Registrations exposes the within-rule action order for contract tests.
func (e *Engine) Registrations() []filter.Registration {
	return append([]filter.Registration(nil), e.regs...)
}

// withBudget bounds one evaluation phase. The budget is per ext_proc
// message, not per filter invocation: the flag's contract is that the
// extension answers (or is cancelled) before Envoy's message_timeout,
// which only a phase-wide bound can honor — per-invocation budgets sum
// past it. It also prices to one context per phase instead of one per
// filter call.
func (e *Engine) withBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if e.budget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, e.budget)
}

type pausedInvocation struct {
	regIdx int
	reg    filter.Registration
	f      filter.Filter
	id     filter.UnitID
	cfg    any
}

type evalCursor struct {
	unit int
	reg  int
}

type requestContinuation struct {
	units  []Unit
	next   evalCursor
	paused pausedInvocation
}

// RequestHeadersResult is the outcome of the headers phase.
type RequestHeadersResult struct {
	Disposition Disposition
	// Reply is valid when Disposition is Blocked. Bypassed preserves mutations
	// produced by earlier actions and skips all later actions and rules.
	Reply filter.Reply
	// HeaderOps is the net-effect folded mutation set, ready for a single
	// proto translation.
	HeaderOps []filter.HeaderOp
	// ClearRouteCache is true when any accumulated mutation asked for it
	// (e.g. a :path rewrite); the adapter must set clear_route_cache.
	ClearRouteCache bool
	// Body: nil = unchanged; non-nil (including empty) = replace, the same
	// sentinel as filter.Mutation.Body. The last executed action to set one
	// wins.
	Body []byte
	// BodyNeed is BodyComplete when evaluation paused for the request body.
	// The adapter maps it to the buffered ext_proc body delivery mode.
	BodyNeed filter.BodyNeed

	continuation *requestContinuation
}

// NeedsBody reports whether evaluation paused for the request body.
func (r *RequestHeadersResult) NeedsBody() bool { return r.BodyNeed != filter.BodyNone }

// RequestBodyResult is the outcome of the body phase.
type RequestBodyResult struct {
	Disposition     Disposition
	Reply           filter.Reply
	HeaderOps       []filter.HeaderOp
	ClearRouteCache bool
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body []byte
}

// record writes a unit action into the stream's info, when one is attached.
func record(st *filter.Stream, id filter.UnitID, filterName, kind string) {
	if st.Info != nil {
		st.Info.RecordUnitAction(id, filterName, kind)
	}
}

func promote(st *filter.Stream, d Disposition) {
	if st.Info != nil {
		st.Info.Promote(d)
	}
}

// EvalRequestHeaders walks (rule, action) pairs in order. The first body
// request pauses the cursor; EvalRequestBody resumes at exactly that point.
func (e *Engine) EvalRequestHeaders(ctx context.Context, st *filter.Stream, units []Unit) (*RequestHeadersResult, error) {
	if err := e.validateUnits(units); err != nil {
		return &RequestHeadersResult{}, err
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	walk, err := e.walkRequestHeaders(ctx, st, units, evalCursor{}, nil)
	res := &RequestHeadersResult{
		Disposition:  walk.disposition,
		Reply:        walk.reply,
		BodyNeed:     walk.bodyNeed,
		continuation: walk.continuation,
	}
	foldRequestHeaders(res, walk.pending)
	if res.Disposition == DispositionPassthrough && len(walk.pending) > 0 {
		res.Disposition = DispositionMutated
		promote(st, DispositionMutated)
	}
	return res, err
}

type requestWalk struct {
	disposition  Disposition
	reply        filter.Reply
	pending      []filter.Mutation
	bodyNeed     filter.BodyNeed
	continuation *requestContinuation
}

func (e *Engine) walkRequestHeaders(ctx context.Context, st *filter.Stream, units []Unit, start evalCursor, body *filter.Body) (requestWalk, error) {
	walk := requestWalk{disposition: DispositionPassthrough}
	for u := start.unit; u < len(units); u++ {
		regStart := 0
		if u == start.unit {
			regStart = start.reg
		}
		for regIdx := regStart; regIdx < len(e.regs); regIdx++ {
			reg := e.regs[regIdx]
			cfg := units[u].Cfgs[regIdx]
			if cfg == nil || reg.Phases&filter.PhaseRequestHeaders == 0 {
				continue
			}
			erased := filter.ErasedRuleConfig{ID: units[u].ID, Cfg: cfg, Scope: units[u].Scope}
			f := reg.New(erased)
			act, invokeErr := e.invoke(ctx, st, e.metrics[regIdx].requestHeaders, func(ctx context.Context) (filter.Action, error) {
				return f.OnRequestHeaders(ctx, st)
			})
			if invokeErr != nil {
				if open, err := e.resolveFailure(st, reg, cfg, units[u].ID, &walk.disposition, invokeErr); !open {
					return walk, err
				}
				continue
			}
			next := nextCursor(evalCursor{unit: u, reg: regIdx}, len(e.regs))
			if act.Kind() == filter.KindNeedBody {
				if err := validateBodyRequest(reg); err != nil {
					return walk, err
				}
				walk.pending = append(walk.pending, act.Mutations()...)
				record(st, units[u].ID, reg.Name, ActionNeedBody)
				if body == nil {
					walk.bodyNeed = reg.Body
					walk.continuation = &requestContinuation{
						units:  append([]Unit(nil), units...),
						next:   next,
						paused: pausedInvocation{regIdx: regIdx, reg: reg, f: f, id: units[u].ID, cfg: cfg},
					}
					return walk, nil
				}
				bodyAct, bodyErr := e.invoke(ctx, st, e.metrics[regIdx].requestBody, func(ctx context.Context) (filter.Action, error) {
					return f.OnRequestBody(ctx, st, *body)
				})
				stop, err := e.applyRequestAction(st, reg, cfg, units[u].ID, bodyAct, bodyErr, &walk)
				if err != nil || stop {
					return walk, err
				}
				continue
			}
			stop, err := e.applyRequestAction(st, reg, cfg, units[u].ID, act, nil, &walk)
			if err != nil || stop {
				return walk, err
			}
		}
	}
	if len(walk.pending) > 0 {
		walk.disposition = DispositionMutated
		promote(st, DispositionMutated)
	}
	return walk, nil
}

func (e *Engine) applyRequestAction(st *filter.Stream, reg filter.Registration, cfg any, id filter.UnitID, act filter.Action, invokeErr error, walk *requestWalk) (bool, error) {
	if invokeErr != nil {
		open, err := e.resolveFailure(st, reg, cfg, id, &walk.disposition, invokeErr)
		return !open, err
	}
	switch act.Kind() {
	case filter.KindStop:
		walk.reply, _ = act.Reply()
		walk.disposition = DispositionBlocked
		walk.pending = nil
		promote(st, DispositionBlocked)
		record(st, id, reg.Name, ActionBlock)
		return true, nil
	case filter.KindBypass:
		walk.disposition = DispositionBypassed
		promote(st, DispositionBypassed)
		record(st, id, reg.Name, ActionBypass)
		return true, nil
	case filter.KindNeedBody:
		return true, fmt.Errorf("filter %q returned NeedBody from the body phase; NeedBody is only legal on request headers", reg.Name)
	case filter.KindContinue:
		if len(act.Mutations()) > 0 {
			walk.pending = append(walk.pending, act.Mutations()...)
			record(st, id, reg.Name, ActionMutate)
		}
		return false, nil
	default:
		return true, fmt.Errorf("filter %q returned unknown action kind %d", reg.Name, act.Kind())
	}
}

// EvalRequestBody resumes the single filter that paused on headers, then
// continues the remaining rules in their original order.
func (e *Engine) EvalRequestBody(ctx context.Context, st *filter.Stream, prior *RequestHeadersResult, body filter.Body) (*RequestBodyResult, error) {
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	res := &RequestBodyResult{Disposition: DispositionPassthrough}
	if prior == nil || prior.continuation == nil {
		return res, nil
	}
	cont := prior.continuation
	paused := cont.paused
	walk := requestWalk{disposition: DispositionPassthrough}
	act, invokeErr := e.invoke(ctx, st, e.metrics[paused.regIdx].requestBody, func(ctx context.Context) (filter.Action, error) {
		return paused.f.OnRequestBody(ctx, st, body)
	})
	stop, err := e.applyRequestAction(st, paused.reg, paused.cfg, paused.id, act, invokeErr, &walk)
	if err == nil && !stop {
		remaining, walkErr := e.walkRequestHeaders(ctx, st, cont.units, cont.next, &body)
		if remaining.disposition == DispositionBlocked {
			walk.pending = nil
		} else {
			walk.pending = append(walk.pending, remaining.pending...)
		}
		walk.disposition, walk.reply = remaining.disposition, remaining.reply
		err = walkErr
	}
	res.Disposition, res.Reply = walk.disposition, walk.reply
	foldRequestBody(res, walk.pending)
	if res.Disposition == DispositionPassthrough && len(walk.pending) > 0 {
		res.Disposition = DispositionMutated
		promote(st, DispositionMutated)
	}
	return res, err
}

// EvalResponseHeaders dispatches the response-headers phase to every supplied
// unit whose registration declared it. Each call uses a fresh filter instance;
// response-header filters therefore must not depend on request-phase instance
// state.
func (e *Engine) EvalResponseHeaders(ctx context.Context, st *filter.Stream, units []Unit) error {
	if err := e.validateUnits(units); err != nil {
		return err
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	for u := range units {
		for regIdx, reg := range e.regs {
			if reg.Phases&filter.PhaseResponseHeaders == 0 || units[u].Cfgs[regIdx] == nil {
				continue
			}
			cfg := filter.ErasedRuleConfig{
				ID:    units[u].ID,
				Cfg:   units[u].Cfgs[regIdx],
				Scope: units[u].Scope,
			}
			f := reg.New(cfg)
			act, err := e.invoke(ctx, st, e.metrics[regIdx].responseHeaders, func(ctx context.Context) (filter.Action, error) {
				return f.OnResponseHeaders(ctx, st)
			})
			if err != nil {
				if open, tErr := e.translate(reg, cfg.Cfg, err); !open {
					return tErr
				}
				continue
			}
			if act.Kind() != filter.KindContinue || len(act.Mutations()) > 0 {
				return fmt.Errorf("filter %q: response-headers currently supports observation only", reg.Name)
			}
		}
	}
	return nil
}

func (e *Engine) validateUnits(units []Unit) error {
	for i := range units {
		if len(units[i].Cfgs) != len(e.regs) {
			return fmt.Errorf("unit %q config count %d does not match registration count %d",
				units[i].ID.String(), len(units[i].Cfgs), len(e.regs))
		}
	}
	return nil
}

func nextCursor(cur evalCursor, regs int) evalCursor {
	cur.reg++
	if cur.reg == regs {
		cur.unit++
		cur.reg = 0
	}
	return cur
}

func validateBodyRequest(reg filter.Registration) error {
	if reg.Body == filter.BodyNone || reg.Phases&filter.PhaseRequestBody == 0 {
		return fmt.Errorf("filter %q returned NeedBody without declaring request-body support", reg.Name)
	}
	return nil
}

func foldRequestHeaders(res *RequestHeadersResult, pending []filter.Mutation) {
	res.HeaderOps = Fold(pending)
	res.ClearRouteCache = anyClearRouteCache(pending)
	res.Body = lastBodyMutation(pending)
}

func foldRequestBody(res *RequestBodyResult, pending []filter.Mutation) {
	res.HeaderOps = Fold(pending)
	res.ClearRouteCache = anyClearRouteCache(pending)
	res.Body = lastBodyMutation(pending)
}

func anyClearRouteCache(muts []filter.Mutation) bool {
	for _, m := range muts {
		if m.ClearRouteCache {
			return true
		}
	}
	return false
}

// lastBodyMutation returns the last non-nil body replacement in execution
// order; nil means unchanged, non-nil (including empty) means replace.
func lastBodyMutation(muts []filter.Mutation) []byte {
	var body []byte
	for _, m := range muts {
		if m.Body != nil {
			body = m.Body
		}
	}
	return body
}

// translate resolves a filter error against its failure policy. Returns
// open=true when evaluation should continue (FailOpen), otherwise the error
// to surface (FailClosed). cfg may be nil when no config is at hand; a
// FromRule policy without a config falls back to FailClosed.
func (e *Engine) translate(reg filter.Registration, cfg any, err error) (open bool, out error) {
	policy := reg.OnError
	if policy == filter.FromRule {
		if cfg == nil {
			policy = filter.FailClosed
		} else {
			policy = reg.PolicyFor(cfg)
		}
	}
	if policy == filter.FailOpen {
		return true, nil
	}
	return false, fmt.Errorf("filter %q: %w", reg.Name, err)
}

// resolveFailure runs a filter error through its failure policy: fail-open
// records the skip and lets the walk continue; fail-closed resolves the
// stream as an error via the given disposition slot.
func (e *Engine) resolveFailure(st *filter.Stream, reg filter.Registration, cfg any,
	id filter.UnitID, d *Disposition, err error) (open bool, tErr error) {
	open, tErr = e.translate(reg, cfg, err)
	if !open {
		*d = DispositionError
		promote(st, DispositionError)
		return false, tErr
	}
	record(st, id, reg.Name, ActionErrorOpen)
	return true, nil
}
