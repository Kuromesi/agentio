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

import "slices"

// ActionKind names what a filter decided. It is only readable through
// Action accessors; filters never construct an Action from a kind.
type ActionKind uint8

const (
	// KindContinue lets the chain proceed, optionally with mutations.
	KindContinue ActionKind = iota
	// KindStop terminates the request and discards pending mutations
	// (block semantics).
	KindStop
	// KindBypass skips all following actions and rules while preserving work
	// already performed by earlier rules.
	KindBypass
	// KindNeedBody asks the framework to deliver the request body before this
	// filter can decide, and suspends the walk here so no later rule acts before
	// this one's verdict. Only legal from request headers.
	//
	// Body subscription stays a runtime action, unlike the response-headers phase
	// which is declared from config by Descriptor.SubscribesOf. The reason is
	// recoverability, not history: once any rule has asked for the body it is in
	// hand, so a later filter's NeedBody is satisfied inline and nothing is lost by
	// discovering the need late. A response-headers subscription discovered late is
	// unsatisfiable, because Envoy honours mode_override only on a header-phase reply
	// and response_header_mode is only useful on the request-headers one. Keeping
	// this runtime is also what lets a body decision fail through the rule's own
	// failure policy, which a pure config function cannot express.
	//
	// These two are not the whole space. A response *body* want would be a third
	// case: recoverable like the request body, but from the response-headers reply
	// rather than inline, since that reply is also a header-phase reply and can carry
	// an override. Adding it should relax "only legal from request headers" here
	// rather than widen engine.SubscribablePhases.
	KindNeedBody
)

// Action is opaque: fields are private and only the constructors below can
// produce one, so the invariants each kind documents hold by construction.
type Action struct {
	kind      ActionKind
	mutations []Mutation
	reply     Reply
}

// Continue proceeds, accumulating the given mutations in execution order.
func Continue(m ...Mutation) Action {
	return Action{kind: KindContinue, mutations: m}
}

// Stop terminates with the given reply and discards pending mutations.
// It deliberately accepts no mutations: a block never mutates.
func Stop(r Reply) Action {
	return Action{kind: KindStop, reply: r}
}

// Bypass skips all following actions and rules. Earlier mutations and side
// effects are preserved.
func Bypass() Action { return Action{kind: KindBypass} }

// NeedBody asks for the request body, optionally carrying mutations
// accumulated so far.
func NeedBody(m ...Mutation) Action { return Action{kind: KindNeedBody, mutations: m} }

// Kind reports what the filter decided.
func (a Action) Kind() ActionKind { return a.kind }

// Mutations returns the mutations carried by a Continue or NeedBody action.
func (a Action) Mutations() []Mutation { return a.mutations }

// Reply returns the blocking reply and whether one is present.
func (a Action) Reply() (Reply, bool) { return a.reply, a.kind == KindStop }

// Equal reports semantic equality, for test assertions.
func (a Action) Equal(b Action) bool {
	if a.kind != b.kind {
		return false
	}
	if a.kind == KindStop && !a.reply.equal(b.reply) {
		return false
	}
	return slices.EqualFunc(a.mutations, b.mutations, Mutation.equal)
}
