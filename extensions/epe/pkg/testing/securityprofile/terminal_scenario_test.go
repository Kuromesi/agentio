// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Full-chain terminal-action scenarios (Block / Bypass short-circuit
// semantics and passthrough fallbacks) driven through the enginetest
// harness with the production filter chain; see
// extensions/epe/pkg/testing/enginetest/doc.go for the layering
// convention.
package securityprofile

import (
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// blockedAppProfileYAML renders a SecurityProfile named "p1" in namespace
// "default" selecting app=blocked pods, with the given rules block appended
// verbatim (each rule indented under "rules:").
func blockedAppProfileYAML(rulesYAML string) string {
	return `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: p1
  namespace: default
spec:
  selector:
    matchLabels:
      app: blocked
  rules:
` + rulesYAML
}

// otherSelectorProfileYAML is a profile whose selector matches no test pod
// (app=other), used by the no-profile-match passthrough scenarios.
const otherSelectorProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: p1
  namespace: default
spec:
  selector:
    matchLabels:
      app: other
`

// blockedPeerRequest builds a request from the default/pod-x pod carrying
// the app=blocked label, matching blockedAppProfileYAML's selector.
func blockedPeerRequest(method, host, path string) *enginetest.RequestBuilder {
	return enginetest.NewRequest(method, host, path).
		Peer("default", "pod-x", map[string]string{"app": "blocked"})
}

func TestHandleRequestHeaders_BlockMatched(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: block-secret-path
    match:
    - domains:
      - "*"
      paths:
      - type: Prefix
        value: /admin
      methods:
      - GET
    actions:
      block:
        statusCode: 451
        body: '{"error":"forbidden"}'
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/admin/keys"))
	verdict.RequireBlocked(t, 451)
	if want := `{"error":"forbidden"}`; verdict.ImmediateBody != want {
		t.Errorf("body: want %q, got %q", want, verdict.ImmediateBody)
	}
}

func TestHandleRequestHeaders_BlockNotMatched_FallsThrough(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: block-admin
    match:
    - domains:
      - "*"
      paths:
      - type: Prefix
        value: /admin
      methods:
      - GET
    actions:
      block:
        statusCode: 403
`))

	h.Run(t, blockedPeerRequest("POST", "api.example.com", "/v1/chat")).
		RequirePassthrough(t)
}

// TestHandleRequestHeaders_NoProfileMatch verifies the passthrough path when
// no profile selector matches the pod labels.
func TestHandleRequestHeaders_NoProfileMatch(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(otherSelectorProfileYAML)

	h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x")).
		RequirePassthrough(t)
}

// TestHandleRequestHeaders_RuleWithEmptyActions covers the passthrough path
// when a rule matches but its Actions struct is zero-valued (no Block, no
// Bypass): every filter returns Continue and the request falls through.
func TestHandleRequestHeaders_RuleWithEmptyActions(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: no-actions
    match:
    - domains:
      - "*"
    actions: {}
`))

	h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x")).
		RequirePassthrough(t)
}

// TestHandleRequestHeaders_BypassMatched_ForwardsUnmodified verifies a Bypass
// rule short-circuits the chain with a passthrough response (NOT an
// ImmediateResponse, which would terminate the request).
func TestHandleRequestHeaders_BypassMatched_ForwardsUnmodified(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: trust-internal
    match:
    - domains:
      - internal.local
    actions:
      bypass: true
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "internal.local", "/anything"))
	verdict.RequireBypassed(t)
	// The subject is the exemption itself, and "bypassed" alone only means
	// matched-but-unmodified: name the action that produced it.
	verdict.RequireAction(t, ":bypass:")
}

// TestHandleRequestHeaders_BypassNotMatched_FallsThroughToBlock verifies the
// bypass filter only short-circuits when the rule explicitly opts in. A rule
// that has Block but no Bypass must still produce the Block response.
func TestHandleRequestHeaders_BypassNotMatched_FallsThroughToBlock(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: block-only
    match:
    - domains:
      - "*"
    actions:
      block:
        statusCode: 403
`))

	h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x")).
		RequireBlocked(t, 403)
}

// TestHandleRequestHeaders_BypassBeatsBlockSameRule verifies that when a
// single rule pathologically declares both Bypass=true and a Block action,
// Bypass wins because it runs ahead of Block in the production chain.
func TestHandleRequestHeaders_BypassBeatsBlockSameRule(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: bypass-and-block
    match:
    - domains:
      - "*"
    actions:
      bypass: true
      block:
        statusCode: 403
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x"))
	verdict.RequireBypassed(t)
	// Bypass beating Block within the rule is the claim, so the bypass action
	// has to be the one on record.
	verdict.RequireAction(t, ":bypass:")
}

// TestHandleRequestHeaders_BypassRuleSkipsLaterBlockRule verifies cross-rule
// short-circuit semantics: an earlier Bypass rule prevents a later Block rule
// from running, even though the Block rule would otherwise match.
func TestHandleRequestHeaders_BypassRuleSkipsLaterBlockRule(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: bypass-internal-first
    match:
    - domains:
      - internal.local
    actions:
      bypass: true
  - name: block-everything-else
    match:
    - domains:
      - "*"
    actions:
      block:
        statusCode: 403
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "internal.local", "/anything"))
	verdict.RequireBypassed(t)
	// The earlier bypass rule is what must have fired, not merely some rule
	// that matched and left the wire alone.
	verdict.RequireAction(t, ":bypass:")
}

// TestHandleRequestHeaders_BlockRuleBeatsLaterBypassRule sanity-checks the
// reverse order: a Block rule that matches first must short-circuit before
// the engine ever reaches a later Bypass rule.
func TestHandleRequestHeaders_BlockRuleBeatsLaterBypassRule(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: block-first
    match:
    - domains:
      - "*"
    actions:
      block:
        statusCode: 451
  - name: bypass-second
    match:
    - domains:
      - "*"
    actions:
      bypass: true
`))

	h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x")).
		RequireBlocked(t, 451)
}
