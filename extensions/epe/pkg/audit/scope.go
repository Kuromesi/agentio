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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"

	"istio.io/istio/extensions/epe/pkg/inputs"
)

// Scope is the template root passed to URL / header / body renderers and
// the CEL `when` evaluator. It embeds the shared inputs.Scope, so the
// promoted Request/Pod/Profile/Rule accessor methods resolve the documented
// template paths ({{ .Request.* }}, {{ .Pod.* }}, ...) — text/template treats
// an exported method exactly as it treats an exported field. Those accessors
// take value receivers, so they promote through the embedded value whether the
// render root is a *Scope or a Scope value; TestAuditScopeRendersTemplatePaths
// pins both. All fields are populated at request-resolution time and are safe
// for read-only template access.
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

// Activation shadows the embedded inputs.Scope.Activation: the audit projection
// additionally exposes the audit-only `result` and `response` variables. They
// are layered as a hierarchical child rather than written into the base, so the
// base stays immutable and shared with the unit's Scope — which is what makes
// audit see the request exactly as it was evaluated at request time.
//
// This is where every phase-varying variable belongs; the rule is stated on
// inputs.Scope.buildBag, the site it constrains.
func (s *Scope) Activation() cel.Activation {
	top, err := cel.NewActivation(map[string]any{
		"result":   s.Result,
		"response": map[string]any{"status": s.Response.Status},
	})
	if err != nil {
		// Unreachable: NewActivation rejects only nil and non-map bindings.
		panic("audit: activation: " + err.Error())
	}
	return layer(s.Scope.Activation(), top)
}

// layer is the one place the base/child order is written down. Activation goes
// through it so a test can pin the direction with a deliberately colliding
// child: the embedded inputs.Scope is a concrete value, so a test cannot reach
// the collision through Activation itself, and today's two key sets are
// disjoint, which leaves NewHierarchicalActivation's arguments swappable with
// every test still green. TestAuditScopeActivationShadowsResult's shadowing
// subtest calls layer directly to close that.
func layer(base, child cel.Activation) cel.Activation {
	return interpreter.NewHierarchicalActivation(base, child)
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
