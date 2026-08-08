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
// Package audit hosts the audit domain entities of the SecurityProfile
// Audit action: an asynchronous, fire-and-forget callback fired after a
// matched request resolves. Audit never alters the upstream response.
//
// The stream logger that observes matched rules and emits events lives in
// pkg/policy/securityprofile, beside the binder that resolves them; sink
// implementations (e.g. the webhook dispatcher) consume the Event/Scope types
// defined here.
package audit

import (
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// Scope is the template root passed to URL / header / body renderers and
// the CEL `when` evaluator. It embeds the shared inputs.Scope, so the
// promoted Request/Pod/Profile/Rule fields resolve the documented template
// paths ({{ .Request.* }}, {{ .Pod.* }}, ...). All fields are populated at
// request-resolution time and are safe for read-only template access.
type Scope struct {
	inputs.Scope
	Result  string
	Matched Match
	// Response carries the upstream response view once the response side
	// delivered it; zero Status means "no response observed".
	Response Response
}

// Response is the response-side view exposed to CEL as `response`.
type Response struct {
	Status int
}

// Activation shadows the embedded inputs.Scope.Activation: the audit
// projection additionally exposes the audit-only `result` variable. The
// returned map is pooled; the caller must invoke the returned release
// function when done.
func (s *Scope) Activation() (map[string]any, func()) {
	act := inputs.NewActivationWithInputs(s.Request, s.Pod, s.Profile, s.Rule, s.Inputs, s.Result)
	act["response"] = map[string]any{"status": s.Response.Status}
	return act, func() { inputs.ReleaseActivation(act) }
}

// MatchedCriteria is a template-compatibility accessor: documented webhook
// templates reference {{ .MatchedCriteria.* }}, so it must keep returning
// Matched.
func (s *Scope) MatchedCriteria() Match {
	return s.Matched
}

// Match reports the matched RuleMatch entry as a flat view.
// A field is left zero when the RuleMatch did not constrain that
// dimension.
type Match struct {
	Host        string
	Method      string
	Path        string
	Port        int32
	Headers     map[string]string
	QueryParams map[string]string
}
