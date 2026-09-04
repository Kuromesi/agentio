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

// Scenario tests drive the real extproc.Server over a scripted Envoy stream
// with mcpacl's own payload schema — no policy CRD. They pin the body-phase
// interaction mcpacl owns: the filter asks Envoy for the request body, the
// JSON-RPC document is judged against the rules, and the deny reaches the
// wire as an immediate response while an allowed call passes through.
package mcpacl_test

import (
	"fmt"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

const aclPayload = `{
	"defaultAction": "deny",
	"rules": [{"method": "tools/call", "toolNames": ["safe-tool"], "action": "allow"}]
}`

func toolCall(tool string) *enginetest.RequestBuilder {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":%q}}`, tool)
	return enginetest.NewRequest("POST", "mcp.example.com", "/mcp").
		Header("content-type", "application/json").
		Header("mcp-protocol-version", "2025-11-25").
		Peer("test-ns", "sandbox-a", map[string]string{"app": "sandbox"}).
		Body([]byte(body))
}

// requireWireUntouched asserts the request reached the wire unmodified. The
// access-log outcome is deliberately not asserted: this harness always
// resolves one unit, so an untouched request logs as "bypassed" (policy
// matched, changed nothing), which RequirePassthrough reserves for streams no
// policy selected.
func requireWireUntouched(t *testing.T, verdict *enginetest.Verdict) {
	t.Helper()
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	if verdict.Kind != enginetest.VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough on the wire (raw=%v)", verdict.Kind, verdict.Raw)
	}
	if len(verdict.RequestHeaderOps) != 0 {
		t.Fatalf("RequestHeaderOps = %+v, want none", verdict.RequestHeaderOps)
	}
}

func newACLHarness(t *testing.T) *enginetest.Harness {
	t.Helper()
	return enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: mcpacl.Definition(),
		Payload:    aclPayload,
	})
}

func TestScenario_AllowedToolCallPassesThrough(t *testing.T) {
	requireWireUntouched(t, newACLHarness(t).Run(t, toolCall("safe-tool")))
}

func TestScenario_DeniedToolCallBlockedOnWire(t *testing.T) {
	verdict := newACLHarness(t).Run(t, toolCall("forbidden-tool"))
	verdict.RequireBlocked(t, 403)
	if verdict.Err != nil {
		t.Fatalf("a denied tool call must not be a processing error: %v", verdict.Err)
	}
}

// A non-MCP request on the same rule must not pay the body detour: a GET
// without a JSON-RPC body passes through untouched.
func TestScenario_NonMCPRequestPassesThrough(t *testing.T) {
	requireWireUntouched(t, newACLHarness(t).Run(t,
		enginetest.NewRequest("GET", "mcp.example.com", "/healthz").
			Peer("test-ns", "sandbox-a", map[string]string{"app": "sandbox"})))
}
