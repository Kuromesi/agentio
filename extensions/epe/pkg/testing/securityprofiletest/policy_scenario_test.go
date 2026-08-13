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

// Full-chain orchestration scenarios driven through the enginetest
// harness; see extensions/epe/pkg/testing/enginetest/doc.go for the
// test layering convention.
package securityprofiletest

import (
	"fmt"
	"testing"

	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

const bypassDropsBodyProfile = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: bypass-drops-body
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: mcp-needs-body
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /guarded
      methods:
      - POST
    actions:
      mcpToolPolicy:
        defaultAction: deny
        denyResponse:
          statusCode: 452
          body: denied-guarded
        rules:
        - method: tools/call
          toolNames:
          - allowed-tool
          action: allow
%s`

const trailingBypassRule = `  - name: bypass-everything
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /guarded
    actions:
      bypass: true
`

func guardedMCPRequest() *enginetest.RequestBuilder {
	return enginetest.NewRequest("POST", "server.example.com", "/guarded").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("mcp-protocol-version", "2025-11-25").
		Body([]byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"unlisted-tool"}}`))
}

// TestScenario_LaterBypassCannotSkipEarlierBodyRule proves that bypass only
// skips following rules; it cannot discard an earlier deferred ACL decision.
func TestScenario_LaterBypassCannotSkipEarlierBodyRule(t *testing.T) {
	// Control: without the bypass rule the MCP policy buffers the body
	// and denies the unlisted tool.
	control := New(t, Options{})
	control.Fixture.ApplyYAML(fmt.Sprintf(bypassDropsBodyProfile, ""))
	verdict := control.Run(t, guardedMCPRequest())
	verdict.RequireBlockedBody(t, 452, "denied-guarded")
	if verdict.ModeOverride == nil {
		t.Fatal("control: expected body-mode override for the MCP rule")
	}

	// A later bypass cannot retroactively suppress the earlier MCP rule.
	bypassed := New(t, Options{})
	bypassed.Fixture.ApplyYAML(fmt.Sprintf(bypassDropsBodyProfile, trailingBypassRule))
	verdict = bypassed.Run(t, guardedMCPRequest())
	verdict.RequireBlockedBody(t, 452, "denied-guarded")
	if verdict.ModeOverride == nil {
		t.Fatal("earlier MCP rule did not request body mode")
	}
}

// TestScenario_DestinationPortOverridesAuthority proves a forged :authority
// port cannot dodge a port-scoped rule when the Envoy-authenticated
// destination.port attribute disagrees.
func TestScenario_DestinationPortOverridesAuthority(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: port-rule
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: port-80
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /port
      ports:
      - 80
    actions:
      block:
        statusCode: 418
        body: blocked-port
`)

	spoofed := enginetest.NewRequest("GET", "server.example.com:8080", "/port").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		DestinationPort(80)
	h.Run(t, spoofed).RequireBlockedBody(t, 418, "blocked-port")

	realPort := enginetest.NewRequest("GET", "server.example.com", "/port").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		DestinationPort(8080)
	h.Run(t, realPort).RequirePassthrough(t)
}
