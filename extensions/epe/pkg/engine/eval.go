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

// SubscribablePhases is the set of phases a config may ask Envoy to deliver.
//
// It is deliberately narrower than DispatchedPhases. Request headers arrive
// unconditionally, so nothing subscribes to them. The request body is subscribed at
// runtime through a NeedBody action instead, because a body want discovered late is
// still satisfiable while a response-headers want is not — see Descriptor.SubscribesOf
// for why that asymmetry must not be unified away.
//
// Response headers are the only phase with no late recovery, and that is a property
// of what a mode_override can still change rather than of the response direction.
// Envoy honours mode_override on any header-phase reply: the gate is
// inHeaderProcessState(), true when EITHER direction is awaiting a headers reply, so
// the response-headers reply is a second override opportunity. Setting
// response_header_mode there is pointless — that phase has already begun — but
// response_body_mode is not. So do NOT widen this constant to cover a response body:
// that want is recoverable at response-headers time and belongs closer to NeedBody.
// Response trailers are unverified; check the gate before assuming either way.
const SubscribablePhases = filter.PhaseResponseHeaders

// responseTarget names one (rule, registration) pair the response-headers phase
// must dispatch to, by position in the units slice the caller passed.
type responseTarget struct {
	unit   int
	regIdx int
}

// responseTargets is the shared subscription predicate: it answers, for one set
// of units, which pairs need the response-headers phase.
//
// Nothing carries the answer between phases. Subscription is a pure function of
// the projected config — Registration.Subscribes is handed a config and nothing
// else, no stream, no context, no dependencies — and the adapter pins the
// resolved units on the stream for its whole lifetime. Recomputing over pinned
// inputs therefore cannot disagree with the answer the ModeOverride was built
// from, which is why WantsResponseHeaders and EvalResponseHeaders can both just
// call this instead of one handing a set to the other.
//
// That purity is also what makes config-derived subscription correct in the
// first place. Envoy honours mode_override only on a header-phase reply, and
// response_header_mode is only useful on the request-headers one, so that reply is
// this phase's single opportunity. The ordered walk may suspend mid-sequence
// waiting for a request body, so a want derived by *executing* a filter arrives
// after that reply was already sent whenever an earlier rule paused — reachable in
// the production order (bypass, block, mcpacl, headermutation, tokentransform),
// since mcpacl pauses for the body and headermutation follows it.
//
// "Single opportunity" is specific to response headers, not a property of the
// protocol: the response-headers reply can carry an override too. See
// SubscribablePhases.
func (e *Engine) responseTargets(units []Unit) ([]responseTarget, error) {
	var targets []responseTarget
	for u := range units {
		for regIdx, reg := range e.regs {
			cfg := units[u].Cfgs[regIdx]
			if cfg == nil || reg.Subscribes == nil {
				continue
			}
			declared := reg.Subscribes(cfg)
			// Phase is a bitmask, so a config can declare more than the engine
			// currently knows how to open. Reject the surplus rather than ignore
			// it: a declaration that compiles, survives the intersection with
			// Phases, and is then silently dropped is exactly the "configured but
			// inert" failure this mechanism exists to prevent.
			if surplus := declared &^ SubscribablePhases; surplus != 0 {
				return nil, fmt.Errorf("filter %q subscribes to phases %08b the engine cannot open; "+
					"widen engine.SubscribablePhases when it learns to", reg.Name, surplus)
			}
			if declared&filter.PhaseResponseHeaders != 0 {
				targets = append(targets, responseTarget{unit: u, regIdx: regIdx})
			}
		}
	}
	return targets, nil
}

// WantsResponseHeaders reports whether any matched config needs the
// response-headers phase, from the configs alone — it runs no filter.
//
// The adapter calls it before EvalRequestHeaders, and that position is
// load-bearing in one direction only: the returned error means a policy declared
// a phase the engine cannot open, and failing there keeps a malformed policy from
// triggering the side effects an executed walk has (tokentransform fetches
// Secrets and mints credentials). The boolean itself could be computed any time
// before the reply is assembled.
func (e *Engine) WantsResponseHeaders(units []Unit) (bool, error) {
	if err := e.validateUnits(units); err != nil {
		return false, err
	}
	targets, err := e.responseTargets(units)
	return len(targets) > 0, err
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
	// needsBody is true when evaluation paused for the request body. The
	// adapter maps it to the buffered ext_proc body delivery mode.
	needsBody bool

	continuation *requestContinuation
}

// NeedsBody reports whether evaluation paused for the request body.
func (r *RequestHeadersResult) NeedsBody() bool { return r.needsBody }

// RequestBodyResult is the outcome of the body phase.
type RequestBodyResult struct {
	Disposition     Disposition
	Reply           filter.Reply
	HeaderOps       []filter.HeaderOp
	ClearRouteCache bool
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body []byte
}

// ResponseHeadersResult is the outcome of the response-headers phase.
type ResponseHeadersResult struct {
	Disposition Disposition
	// Reply is valid when Disposition is Blocked, which on this phase only the
	// engine's fail-closed policy synthesises — filters may not return Stop
	// here. The adapter turns it into an ImmediateResponse; Envoy holds the
	// upstream response headers while awaiting our reply, so the local reply
	// replaces them.
	Reply filter.Reply
	// HeaderOps is the net-effect folded mutation set for the response
	// headers, ready for a single proto translation. Empty when blocked.
	HeaderOps []filter.HeaderOp
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
		needsBody:    walk.needsBody,
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
	needsBody    bool
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
					walk.needsBody = true
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
				stop, err := e.applyRequestAction(st, reg, regIdx, cfg, units[u].ID, bodyAct, bodyErr, &walk)
				if err != nil || stop {
					return walk, err
				}
				continue
			}
			stop, err := e.applyRequestAction(st, reg, regIdx, cfg, units[u].ID, act, nil, &walk)
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

func (e *Engine) applyRequestAction(st *filter.Stream, reg filter.Registration, regIdx int, cfg any, id filter.UnitID, act filter.Action, invokeErr error, walk *requestWalk) (bool, error) {
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
	stop, err := e.applyRequestAction(st, paused.reg, paused.regIdx, paused.cfg, paused.id, act, invokeErr, &walk)
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

// The deny the engine synthesises when a response-phase filter fails under
// FailClosed. 500 rather than 403 because it is a server-side fault, not a policy
// decision. Both values reach the wire in the ImmediateResponse, so they are
// named here rather than inlined — tests assert on them verbatim, and a literal
// duplicated across engine, adapter and tests would drift.
const (
	responseFailClosedStatus  = 500
	responseFailClosedDetails = "epe_response_headers_failed_closed"
)

// EvalResponseHeaders dispatches the response-headers phase to exactly the
// (rule, registration) pairs whose config subscribed to it — a rule that did not
// subscribe is never invoked, whatever else opened the phase (e.g. a stream
// logger observing upstream status). Dispatch and subscription are separate
// concerns even though both read the same predicate.
//
// Each call uses a fresh filter instance; response-header filters therefore
// must not depend on request-phase instance state. They also may only return
// Continue — see validateResponseAction — and only the engine's failure policy
// synthesises a blocked response result.
//
// There is deliberately no walkResponseHeaders to match walkRequestHeaders. That
// helper exists because the request walk is resumable: it takes a cursor and is
// called twice, once from EvalRequestHeaders and once from EvalRequestBody after a
// pause. This phase cannot pause — NeedBody is illegal here and no verdict can
// suspend the sequence — so there is no cursor, no second caller, and nothing to
// extract. The loop below is the whole walk.
func (e *Engine) EvalResponseHeaders(ctx context.Context, st *filter.Stream, units []Unit) (*ResponseHeadersResult, error) {
	res := &ResponseHeadersResult{Disposition: DispositionPassthrough}
	if err := e.validateUnits(units); err != nil {
		return res, err
	}
	targets, err := e.responseTargets(units)
	if err != nil {
		return res, err
	}
	// Nothing subscribed: the phase was opened by something stream-level, such as
	// --observe-responses wanting the upstream status in the logs. Return before
	// arming the budget so that path costs no timer.
	if len(targets) == 0 {
		return res, nil
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	var pending []filter.Mutation
	for _, target := range targets {
		reg := e.regs[target.regIdx]
		unit := units[target.unit]
		// responseTargets only yields pairs whose config is non-nil and whose
		// Subscribes survived the intersection with Phases in buildRegistration,
		// so a target always has a config and a metrics child. The Phases term is
		// restated anyway: without it, a subscription that somehow escaped that
		// intersection would reach a nil metrics child and panic in invoke.
		if reg.Phases&filter.PhaseResponseHeaders == 0 {
			continue
		}
		cfg := filter.ErasedRuleConfig{
			ID:    unit.ID,
			Cfg:   unit.Cfgs[target.regIdx],
			Scope: unit.Scope,
		}
		f := reg.New(cfg)
		act, invokeErr := e.invoke(ctx, st, e.metrics[target.regIdx].responseHeaders, func(ctx context.Context) (filter.Action, error) {
			return f.OnResponseHeaders(ctx, st)
		})
		if invokeErr != nil {
			open, tErr := e.resolveResponseFailure(st, reg, cfg.Cfg, unit.ID, res, invokeErr)
			if !open {
				return res, tErr
			}
			continue
		}
		if err := validateResponseAction(reg, act); err != nil {
			return res, err
		}
		if len(act.Mutations()) > 0 {
			pending = append(pending, act.Mutations()...)
			record(st, unit.ID, reg.Name, ActionMutate)
		}
	}
	// Fold resolves Envoy's removes-before-sets ordering; nothing in it is
	// request-specific.
	res.HeaderOps = Fold(pending)
	if len(pending) > 0 {
		res.Disposition = DispositionMutated
		promote(st, DispositionMutated)
	}
	return res, nil
}

// resolveResponseFailure runs a response-phase filter error through its declared
// failure policy. It is the response-side counterpart of resolveFailure, and the
// one difference is the point of the phase: fail-closed does not merely resolve the
// stream as an error, it synthesises a blocking Reply. Envoy holds the upstream
// response headers while awaiting our answer, so that reply genuinely replaces
// them rather than arriving after the response already went downstream.
//
// Fail-open records the skip, exactly as resolveFailure does, so an error that was
// swallowed by policy is still visible to audit.
func (e *Engine) resolveResponseFailure(st *filter.Stream, reg filter.Registration, cfg any,
	id filter.UnitID, res *ResponseHeadersResult, err error) (open bool, tErr error) {
	open, tErr = e.translate(reg, cfg, err)
	if !open {
		res.Disposition = DispositionBlocked
		res.Reply = filter.Reply{
			Status:  responseFailClosedStatus,
			Details: responseFailClosedDetails,
		}
		promote(st, DispositionBlocked)
		record(st, id, reg.Name, ActionBlock)
		return false, tErr
	}
	record(st, id, reg.Name, ActionErrorOpen)
	return true, nil
}

// validateResponseAction rejects everything a response-headers filter may not
// return. Unlike applyRequestAction, which must be a stateful switch because Stop
// and Bypass change the walk, the only legal kind here is Continue — so there is no
// state to touch and the whole check is a predicate on the action.
//
// Stop, Bypass and NeedBody have no meaning once the upstream response exists.
// ClearRouteCache and Body carry none either: Envoy documents clear_route_cache as
// ignored in the response direction, and a response body mutation would require
// CONTINUE_AND_REPLACE, which disables all further response processing. Every one
// of these is rejected rather than ignored — the adapter drops these fields on this
// path, and a mutation that disappears without a word is exactly the failure mode
// this phase was designed to avoid.
func validateResponseAction(reg filter.Registration, act filter.Action) error {
	if act.Kind() != filter.KindContinue {
		return fmt.Errorf("filter %q returned action kind %d from the response-headers phase; "+
			"only Continue is legal there", reg.Name, act.Kind())
	}
	for _, m := range act.Mutations() {
		if m.ClearRouteCache {
			return fmt.Errorf("filter %q asked to clear the route cache from the "+
				"response-headers phase; routing is already resolved there", reg.Name)
		}
		if m.Body != nil {
			return fmt.Errorf("filter %q returned a body mutation from the "+
				"response-headers phase; only header operations are supported there", reg.Name)
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
	if reg.Phases&filter.PhaseRequestBody == 0 {
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
// to surface (FailClosed). cfg may be nil when no config is at hand;
// Registration.OnError handles that case internally.
//
// A nil OnError is FailClosed. Build always installs a non-nil one, but
// Registration is an exported struct with exported fields, so a hand-built value
// (test helpers, anything bypassing Build) has a nil func — and this runs on the
// request path, where the alternative to defaulting is a panic. Defaulting to
// FailClosed also preserves what the field's zero value meant while it was a
// FailurePolicy rather than a function. Mirrors the reg.Subscribes nil check in
// responseTargets.
func (e *Engine) translate(reg filter.Registration, cfg any, err error) (open bool, out error) {
	if reg.OnError != nil && reg.OnError(cfg) == filter.FailOpen {
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
