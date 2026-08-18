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
// rule in registration order. It owns request and response body continuation,
// the per-phase evaluation budget, the per-invocation metrics wrapper,
// failure-policy reduction, and net-effect mutation folding. It knows the
// filter contract and nothing else — no policy API, no ext_proc protos;
// assembly lives in pkg/wiring.
//
// # Phase subscription and body continuation
//
// A filter can need a phase delivered in two ways, and the split between them
// is deliberate, not historical. It falls out of two facts about Envoy:
//
//  1. Envoy honours mode_override only on a header-phase reply, and
//     response_header_mode is only useful on the request-headers reply. The
//     request-headers reply is therefore the response-headers phase's single
//     opportunity to be opened. The response-headers reply can in turn open
//     response_body_mode, because that future phase has not begun yet.
//  2. Either direction's ordered walk may suspend mid-sequence waiting for its
//     complete buffered body.
//
// Together these mean a phase-want discovered by *executing* a filter arrives
// after the request-headers reply was already sent whenever an earlier rule
// paused — reachable in the production order (bypass, block, mcpacl,
// headermutation, tokentransform), since mcpacl pauses for the body and
// headermutation follows it. The response-headers want therefore cannot be an
// action; it is declared from the projected config up front
// (filter.Registration.Subscribes), before the walk runs.
//
// Request and response bodies stay runtime NeedBody actions. Once a direction
// has its body, every later NeedBody is satisfied inline with that same original
// Body. If headers are end-of-stream, the adapter supplies an empty complete
// Body inline and no continuation is created. This avoids speculative buffering
// for filters whose header decision does not need the body.
//
// A suspended continuation owns all pending mutations. The headers reply emits
// none of them; after the body callback and all later pairs finish, the engine
// folds the complete direction result once. Pending mutations are never applied
// back to Stream or to the Body passed to a later filter, so every filter sees
// the original phase headers and bytes.
//
// Invocation errors are resolved through the registration's FailurePolicy.
// FailOpen records and skips the failed invocation. FailClosed returns a local
// 500 blocked result without an engine error. Contract and protocol faults stay
// on the error channel for the ext_proc adapter and Envoy failure mode.
package engine
