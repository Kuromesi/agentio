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
	// f is the live instance that already ran OnRequestHeaders; the body call
	// MUST reuse it, not rebuild via reg.New, or header-phase instance state is
	// lost (tokentransform's OnRequestBody reads f.pending set on headers).
	f filter.Filter
	// at is the paused pair's own cursor, so a Bypass returned from its
	// resumed body invocation records the right response scope.
	at evalCursor
}

type evalCursor struct {
	unit int
	reg  int
}

// next advances past this pair: the following registration, or the first
// registration of the following unit. It is only needed to resume a paused
// walk; the ordinary walk advances inside the pairs iterator.
func (c evalCursor) next(regs int) evalCursor {
	c.reg++
	if c.reg == regs {
		c.unit++
		c.reg = 0
	}
	return c
}

// pair is one (unit, registration) coordinate plus everything dispatch needs.
type pair struct {
	at   evalCursor
	reg  filter.Registration
	unit Unit
	cfg  any
}

// pairs yields every (unit, registration) pair that carries a config for
// phase, in policy order, starting at start.
func (e *Engine) pairs(units []Unit, start evalCursor, phase filter.Phase) func(func(pair) bool) {
	return func(yield func(pair) bool) {
		for u := start.unit; u < len(units); u++ {
			regStart := 0
			if u == start.unit {
				regStart = start.reg
			}
			for regIdx := regStart; regIdx < len(e.regs); regIdx++ {
				reg := e.regs[regIdx]
				cfg := units[u].Cfgs[regIdx]
				if cfg == nil || reg.Phases&phase == 0 {
					continue
				}
				if !yield(pair{at: evalCursor{unit: u, reg: regIdx}, reg: reg, unit: units[u], cfg: cfg}) {
					return
				}
			}
		}
	}
}

// pairAt builds the pair at one cursor, for callers that already know the
// coordinate (the resumed body invocation, the response-phase targets).
func (e *Engine) pairAt(units []Unit, at evalCursor) pair {
	return pair{at: at, reg: e.regs[at.reg], unit: units[at.unit], cfg: units[at.unit].Cfgs[at.reg]}
}

type requestContinuation struct {
	units  []Unit
	paused pausedInvocation
}

// SubscribablePhases contains phases that configs may request from Envoy.
// Request bodies are requested dynamically through NeedBody.
const SubscribablePhases = filter.PhaseResponseHeaders

// responseTarget names one (rule, registration) pair the response-headers phase
// must dispatch to, by position in the units slice the caller passed.
type responseTarget struct {
	unit   int
	regIdx int
}

// ResponseScope bounds response-header dispatch after a request-phase bypass.
// The zero value is unbounded; last includes the bypassing pair.
type ResponseScope struct {
	bounded bool
	last evalCursor
}

// excludes reports whether the pair at (unit, regIdx) lies strictly after the
// bypass point and is therefore suppressed.
func (s ResponseScope) excludes(unit, regIdx int) bool {
	if !s.bounded {
		return false
	}
	return unit > s.last.unit || (unit == s.last.unit && regIdx > s.last.reg)
}

// validateSubscriptions rejects phases the engine cannot open. Validation is
// independent of ResponseScope, so bypass cannot hide invalid config.
func (e *Engine) validateSubscriptions(units []Unit) error {
	for p := range e.pairs(units, evalCursor{}, filter.DispatchedPhases) {
		if p.reg.Subscribes == nil {
			continue
		}
		if surplus := p.reg.Subscribes(p.cfg) &^ SubscribablePhases; surplus != 0 {
			return fmt.Errorf("filter %q subscribes to phases %08b the engine cannot open; "+
				"widen engine.SubscribablePhases when it learns to", p.reg.Name, surplus)
		}
	}
	return nil
}

// responseTargets returns subscribed response-header pairs within scope.
// Callers must validate subscriptions first.
func (e *Engine) responseTargets(units []Unit, scope ResponseScope) []responseTarget {
	var targets []responseTarget
	for p := range e.pairs(units, evalCursor{}, filter.PhaseResponseHeaders) {
		if p.reg.Subscribes == nil || scope.excludes(p.at.unit, p.at.reg) {
			continue
		}
		if p.reg.Subscribes(p.cfg)&filter.PhaseResponseHeaders != 0 {
			targets = append(targets, responseTarget{unit: p.at.unit, regIdx: p.at.reg})
		}
	}
	return targets
}

// WantsResponseHeaders reports whether any matched config subscribes to
// response headers without invoking filters.
func (e *Engine) WantsResponseHeaders(units []Unit) (bool, error) {
	if err := e.validateUnits(units); err != nil {
		return false, err
	}
	if err := e.validateSubscriptions(units); err != nil {
		return false, err
	}
	return len(e.responseTargets(units, ResponseScope{})) > 0, nil
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
	// ResponseScope bounds response-phase dispatch when this walk bypassed;
	// the zero value is unbounded. The adapter carries it to EvalResponseHeaders.
	ResponseScope ResponseScope
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
	// ResponseScope bounds response-phase dispatch when the resumed walk
	// bypassed; the zero value is unbounded.
	ResponseScope ResponseScope
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

// RequestOption configures one request-headers evaluation.
type RequestOption func(*requestOptions)

type requestOptions struct {
	body *filter.Body
}

// WithAvailableBody tells the walk the request body is already in hand, so a
// NeedBody action is satisfied inline instead of suspending the walk. Pass it
// when Envoy set end_of_stream on the headers message: no body will follow, so
// the empty body is final rather than merely not-yet-arrived.
func WithAvailableBody(b filter.Body) RequestOption {
	return func(o *requestOptions) {
		o.body = &b
	}
}

// EvalRequestHeaders walks (rule, action) pairs in order. The first body
// request pauses the cursor; EvalRequestBody resumes at exactly that point.
// With WithAvailableBody, body requests are satisfied inline and the walk
// never pauses.
func (e *Engine) EvalRequestHeaders(ctx context.Context, st *filter.Stream, units []Unit, opts ...RequestOption) (*RequestHeadersResult, error) {
	if err := e.validateUnits(units); err != nil {
		return &RequestHeadersResult{}, err
	}
	var o requestOptions
	for _, opt := range opts {
		opt(&o)
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	walk, err := e.walkRequest(ctx, st, units, evalCursor{}, o.body)
	res := &RequestHeadersResult{
		Reply:         walk.reply,
		ResponseScope: walk.scope,
		needsBody:     walk.needsBody,
		continuation:  walk.continuation,
	}
	res.HeaderOps, res.ClearRouteCache, res.Body = foldPending(walk.pending)
	res.Disposition = walk.resolved()
	return res, err
}

type requestWalk struct {
	st           *filter.Stream
	disposition  Disposition
	reply        filter.Reply
	pending      []filter.Mutation
	scope        ResponseScope
	needsBody    bool
	continuation *requestContinuation
}

// record and promote save every request-phase call site from restating the
// unit ID and filter name it already has in hand as a pair. StreamInfo's
// mutators tolerate a nil receiver, so no guard is needed here.
func (w *requestWalk) record(p pair, kind string) {
	w.st.Info.RecordUnitAction(p.unit.ID, p.reg.Name, kind)
}

func (w *requestWalk) promote(d Disposition) {
	w.st.Info.Promote(d)
}

// resolved reports the disposition a finished walk settles on: a walk that
// accumulated mutations but reached no verdict is Mutated. It promotes into
// StreamInfo as a side effect, so call it exactly once per walk.
func (w *requestWalk) resolved() Disposition {
	if w.disposition == DispositionPassthrough && len(w.pending) > 0 {
		w.promote(DispositionMutated)
		return DispositionMutated
	}
	return w.disposition
}

// halted reports whether the walk stopped. These three dispositions are the
// complete set that ends a walk; nothing else may.
func (w *requestWalk) halted() bool {
	switch w.disposition {
	case DispositionBlocked, DispositionBypassed, DispositionError:
		return true
	}
	return false
}

// walkRequest is the request-direction walk: it dispatches the request-headers
// phase and, when the body is already in hand, the request-body phase inline.
func (e *Engine) walkRequest(ctx context.Context, st *filter.Stream, units []Unit, start evalCursor, body *filter.Body) (requestWalk, error) {
	walk := requestWalk{st: st, disposition: DispositionPassthrough}
	for p := range e.pairs(units, start, filter.PhaseRequestHeaders) {
		erased := filter.ErasedRuleConfig{ID: p.unit.ID, Cfg: p.cfg, Scope: p.unit.Scope}
		f := p.reg.New(erased)
		act, invokeErr := e.invoke(ctx, st, e.metrics[p.at.reg].requestHeaders, func(ctx context.Context) (filter.Action, error) {
			return f.OnRequestHeaders(ctx, st)
		})
		if invokeErr != nil {
			if ferr := walk.filterFailed(p, invokeErr); ferr != nil {
				return walk, ferr
			}
			continue
		}
		if act.Kind() == filter.KindNeedBody {
			if err := validateBodyRequest(p.reg); err != nil {
				return walk, err
			}
			walk.pending = append(walk.pending, act.Mutations()...)
			walk.record(p, ActionNeedBody)
			if body == nil {
				walk.needsBody = true
				walk.continuation = &requestContinuation{
					units:  append([]Unit(nil), units...),
					paused: pausedInvocation{f: f, at: p.at},
				}
				return walk, nil
			}
			bodyAct, bodyErr := e.invoke(ctx, st, e.metrics[p.at.reg].requestBody, func(ctx context.Context) (filter.Action, error) {
				return f.OnRequestBody(ctx, st, *body)
			})
			if bodyErr != nil {
				if ferr := walk.filterFailed(p, bodyErr); ferr != nil {
					return walk, ferr
				}
				continue
			}
			if err := walk.apply(p, bodyAct); err != nil {
				return walk, err
			}
			if walk.halted() {
				return walk, nil
			}
			continue
		}
		if err := walk.apply(p, act); err != nil {
			return walk, err
		}
		if walk.halted() {
			return walk, nil
		}
	}
	return walk, nil
}

// apply folds one filter's verdict into the walk. A nil error does not mean
// the walk continues — check halted().
func (w *requestWalk) apply(p pair, act filter.Action) error {
	switch act.Kind() {
	case filter.KindStop:
		w.reply, _ = act.Reply()
		w.disposition = DispositionBlocked
		w.pending = nil
		w.promote(DispositionBlocked)
		w.record(p, ActionBlock)
		return nil
	case filter.KindBypass:
		w.disposition = DispositionBypassed
		// The pairs after this one are skipped in this walk AND in the
		// response phase; the scope is how the suppression reaches there.
		w.scope = ResponseScope{bounded: true, last: p.at}
		w.promote(DispositionBypassed)
		w.record(p, ActionBypass)
		return nil
	case filter.KindNeedBody:
		return fmt.Errorf("filter %q returned NeedBody from the body phase; NeedBody is only legal on request headers", p.reg.Name)
	case filter.KindContinue:
		if len(act.Mutations()) > 0 {
			w.pending = append(w.pending, act.Mutations()...)
			w.record(p, ActionMutate)
		}
		return nil
	default:
		return fmt.Errorf("filter %q returned unknown action kind %d", p.reg.Name, act.Kind())
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
	p := e.pairAt(cont.units, paused.at)
	walk := requestWalk{st: st, disposition: DispositionPassthrough}
	act, invokeErr := e.invoke(ctx, st, e.metrics[p.at.reg].requestBody, func(ctx context.Context) (filter.Action, error) {
		return paused.f.OnRequestBody(ctx, st, body)
	})
	var err error
	if invokeErr != nil {
		err = walk.filterFailed(p, invokeErr)
	} else {
		err = walk.apply(p, act)
	}
	if err == nil && !walk.halted() {
		remaining, walkErr := e.walkRequest(ctx, st, cont.units, paused.at.next(len(e.regs)), &body)
		if remaining.disposition == DispositionBlocked {
			walk.pending = nil
		} else {
			walk.pending = append(walk.pending, remaining.pending...)
		}
		walk.disposition, walk.reply, walk.scope = remaining.disposition, remaining.reply, remaining.scope
		err = walkErr
	}
	res.Reply, res.ResponseScope = walk.reply, walk.scope
	res.HeaderOps, res.ClearRouteCache, res.Body = foldPending(walk.pending)
	res.Disposition = walk.resolved()
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

// EvalResponseHeaders invokes subscribed response-header filters within scope
// and folds their header mutations in policy order.
func (e *Engine) EvalResponseHeaders(ctx context.Context, st *filter.Stream, units []Unit, scope ResponseScope) (*ResponseHeadersResult, error) {
	res := &ResponseHeadersResult{Disposition: DispositionPassthrough}
	if err := e.validateUnits(units); err != nil {
		return res, err
	}
	if err := e.validateSubscriptions(units); err != nil {
		return res, err
	}
	targets := e.responseTargets(units, scope)
	// A stream-level observer may open the phase without subscribing any pair.
	if len(targets) == 0 {
		return res, nil
	}
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	var pending []filter.Mutation
	for _, target := range targets {
		p := e.pairAt(units, evalCursor{unit: target.unit, reg: target.regIdx})
		// responseTargets returns only configured response-capable pairs.
		if p.reg.Phases&filter.PhaseResponseHeaders == 0 {
			continue
		}
		f := p.reg.New(filter.ErasedRuleConfig{
			ID:    p.unit.ID,
			Cfg:   p.cfg,
			Scope: p.unit.Scope,
		})
		act, invokeErr := e.invoke(ctx, st, e.metrics[p.at.reg].responseHeaders, func(ctx context.Context) (filter.Action, error) {
			return f.OnResponseHeaders(ctx, st)
		})
		if invokeErr != nil {
			open, tErr := e.resolveResponseFailure(st, p.reg, p.cfg, p.unit.ID, res, invokeErr)
			if !open {
				return res, tErr
			}
			continue
		}
		if err := validateResponseAction(p.reg, act); err != nil {
			return res, err
		}
		if len(act.Mutations()) > 0 {
			pending = append(pending, act.Mutations()...)
			st.Info.RecordUnitAction(p.unit.ID, p.reg.Name, ActionMutate)
		}
	}
	// Fold resolves Envoy's removes-before-sets ordering; nothing in it is
	// request-specific.
	res.HeaderOps = Fold(pending)
	if len(pending) > 0 {
		res.Disposition = DispositionMutated
		st.Info.Promote(DispositionMutated)
	}
	return res, nil
}

// resolveResponseFailure applies the filter's response-phase failure policy.
// FailClosed synthesizes a blocking reply; FailOpen records the error and continues.
func (e *Engine) resolveResponseFailure(st *filter.Stream, reg filter.Registration, cfg any,
	id filter.UnitID, res *ResponseHeadersResult, err error) (open bool, tErr error) {
	if failurePolicy(reg, cfg) == filter.FailOpen {
		st.Info.RecordUnitAction(id, reg.Name, ActionErrorOpen)
		return true, nil
	}
	res.Disposition = DispositionBlocked
	res.Reply = filter.Reply{
		Status:  responseFailClosedStatus,
		Details: responseFailClosedDetails,
	}
	st.Info.Promote(DispositionBlocked)
	st.Info.RecordUnitAction(id, reg.Name, ActionBlock)
	return false, fmt.Errorf("filter %q: %w", reg.Name, err)
}

// validateResponseAction accepts Continue actions containing only response-header mutations.
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

func validateBodyRequest(reg filter.Registration) error {
	if reg.Phases&filter.PhaseRequestBody == 0 {
		return fmt.Errorf("filter %q returned NeedBody without declaring request-body support", reg.Name)
	}
	return nil
}

// foldPending computes the net effect of one walk's accumulated mutations: the
// folded header ops, whether any asked to clear the route cache, and the last
// body replacement (nil = unchanged).
func foldPending(pending []filter.Mutation) (ops []filter.HeaderOp, clearRouteCache bool, body []byte) {
	return Fold(pending), anyClearRouteCache(pending), lastBodyMutation(pending)
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

// failurePolicy applies the registration's error policy. A nil OnError defaults
// to FailClosed.
func failurePolicy(reg filter.Registration, cfg any) filter.FailurePolicy {
	if reg.OnError == nil {
		return filter.FailClosed
	}
	return reg.OnError(cfg)
}

// filterFailed routes a filter error through its policy. A nil return means
// fail-open: the skip was recorded and the walk continues. Fail-closed resolves
// the walk as an error and surfaces the wrapped error.
func (w *requestWalk) filterFailed(p pair, err error) error {
	if failurePolicy(p.reg, p.cfg) == filter.FailOpen {
		w.record(p, ActionErrorOpen)
		return nil
	}
	w.disposition = DispositionError
	w.promote(DispositionError)
	return fmt.Errorf("filter %q: %w", p.reg.Name, err)
}
