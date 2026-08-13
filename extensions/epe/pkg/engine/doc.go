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

// Package engine evaluates rules in policy order and actions within each
// rule in registration order. It owns body-phase cursor continuation, the
// per-invocation budget/metrics wrapper, and net-effect mutation folding.
// It knows the filter contract and nothing else — no policy API, no
// ext_proc protos; assembly lives in pkg/wiring.
//
// # Phase subscription: response headers from config, the request body from an action
//
// A filter can need a phase delivered in two ways, and the split between them
// is deliberate, not historical. It falls out of two facts about Envoy:
//
//  1. Envoy honours mode_override only on a header-phase reply, and
//     response_header_mode is only useful on the request-headers reply. The
//     request-headers reply is therefore the response-headers phase's single
//     opportunity to be opened. "Single opportunity" is specific to response
//     headers, not a property of the protocol: the response-headers reply is
//     itself a header-phase reply and can carry an override too — that is how a
//     future response-body phase would be opened — but it cannot open a phase
//     that needed the earlier reply. (The gate is Envoy's inHeaderProcessState(),
//     true when EITHER direction is awaiting a headers reply; setting
//     response_header_mode on the response-headers reply is pointless — that
//     phase has already begun — but response_body_mode is not.)
//  2. The ordered walk may suspend mid-sequence waiting for a request body.
//
// Together these mean a phase-want discovered by *executing* a filter arrives
// after the request-headers reply was already sent whenever an earlier rule
// paused — reachable in the production order (bypass, block, mcpacl,
// headermutation, tokentransform), since mcpacl pauses for the body and
// headermutation follows it. The response-headers want therefore cannot be an
// action; it is declared from the projected config up front
// (filter.Registration.Subscribes), before the walk runs.
//
// The request body is the opposite case and stays a runtime NeedBody action:
// once any rule has asked for the body it is in hand, so a later filter's
// NeedBody is satisfied inline and nothing is lost by discovering the need
// late. Keeping it runtime is also what lets a body decision fail through its
// rule's own failure policy, which a pure config function cannot express.
// Moving the body want into config would mean buffering speculatively on every
// request whose config merely might need it, and would strand that failure
// policy (see tokentransform's failEligible path).
//
// These two are not the whole space. A response *body* want would be a third
// case: recoverable like the request body, but from the response-headers reply
// rather than inline, since that reply can also carry an override. Adding it
// relaxes "NeedBody is only legal on request headers" rather than widening
// SubscribablePhases.
package engine
