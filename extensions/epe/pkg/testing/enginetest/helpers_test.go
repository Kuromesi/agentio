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

package enginetest

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// auditProfileYAML wires an audit webhook (with URL template, header and
// body rendering) plus one block rule, for exercising the audit helpers.
func auditProfileYAML(receiverURL string) string {
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: audit-profile
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  audit:
  - name: on-block
    when: 'result == "blocked"'
    webhook:
      url: '%s/{{ .Request.Header "x-audit-marker" }}'
      request:
        method: POST
        headers:
        - name: X-Audit-Profile
          value: '{{ .Profile.Name }}'
        body:
          json:
            path: '{{ .Request.Path }}'
            rule: '{{ .Rule.Name }}'
  rules:
  - name: audited-block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /audited
    actions:
      block:
        statusCode: 451
        body: blocked-audited
`, receiverURL)
}

func TestMetricProbe_WebhookDispatchOutcomes(t *testing.T) {
	LockMetrics(t)

	receiver := NewAuditReceiver(t)
	wiring := WireAudit(t, AuditOptions{Mode: AuditSync})
	h := New(t, Options{AuditRouter: wiring.Router})
	h.Fixture.ApplyYAML(auditProfileYAML(receiver.URL("")))

	success := ProbeMetric(t, "epe_audit_webhook_dispatched_total",
		map[string]string{"result": "success"})
	httpError := ProbeMetric(t, "epe_audit_webhook_dispatched_total",
		map[string]string{"result": "http_error"})

	h.Run(t, testRequest("/audited").Header("x-audit-marker", "metric-success")).
		RequireBlocked(t, 451)
	success.RequireDelta(t, 1)
	httpError.RequireDelta(t, 0)

	receiver.SetResponse(http.StatusInternalServerError, "boom")
	h.Run(t, testRequest("/audited").Header("x-audit-marker", "metric-http-error")).
		RequireBlocked(t, 451)
	httpError.RequireDelta(t, 1)
	success.RequireDelta(t, 1)
}

func TestMetricProbe_TransportErrorCounted(t *testing.T) {
	LockMetrics(t)

	wiring := WireAudit(t, AuditOptions{Mode: AuditSync})
	h := New(t, Options{AuditRouter: wiring.Router})
	h.Fixture.ApplyYAML(auditProfileYAML("http://127.0.0.1:1"))

	transportError := ProbeMetric(t, "epe_audit_webhook_dispatched_total",
		map[string]string{"result": "transport_error"})

	h.Run(t, testRequest("/audited").Header("x-audit-marker", "metric-transport")).
		RequireBlocked(t, 451)
	transportError.RequireDelta(t, 1)
}

func TestDeliverySweep_MCPVerdictHoldsInEveryDeliveryShape(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: mcp-sweep
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: default-deny
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /mcp
      methods:
      - POST
    actions:
      mcpToolPolicy:
        defaultAction: deny
        denyResponse:
          statusCode: 452
          body: denied-sweep
        rules:
        - method: tools/call
          toolNames:
          - allowed-tool
          action: allow
`)

	deny := []byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"denied-tool"}}`)
	DeliverySweep(t, deny, func(t *testing.T, withBody func(*RequestBuilder) *RequestBuilder) {
		h.Run(t, withBody(NewRequest("POST", "server.example.com", "/mcp").
			Peer("test-ns", "sandbox-pod", testLabels).
			Header("mcp-protocol-version", "2025-11-25"))).
			RequireBlockedBody(t, 452, "denied-sweep")
	})

	allow := []byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"allowed-tool"}}`)
	DeliverySweep(t, allow, func(t *testing.T, withBody func(*RequestBuilder) *RequestBuilder) {
		verdict := h.Run(t, withBody(NewRequest("POST", "server.example.com", "/mcp").
			Peer("test-ns", "sandbox-pod", testLabels).
			Header("mcp-protocol-version", "2025-11-25")))
		if verdict.Kind == VerdictBlocked {
			t.Fatalf("allowed tool blocked in this delivery shape: %+v", verdict)
		}
	})
}

func TestRunParallel_ConcurrentRequestsDoNotInterfere(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockProfileYAML("parallel-block", "/parallel/blocked", 451, "blocked-parallel", -1))

	const n = 32
	verdicts := h.RunParallel(t, n, func(i int) *RequestBuilder {
		if i%2 == 0 {
			return testRequest("/parallel/blocked")
		}
		return testRequest(fmt.Sprintf("/parallel/open/%d", i))
	})
	for i, verdict := range verdicts {
		if verdict.Err != nil {
			t.Fatalf("request %d: Process error: %v", i, verdict.Err)
		}
		if i%2 == 0 {
			if verdict.Kind != VerdictBlocked || verdict.ImmediateStatus != 451 {
				t.Errorf("request %d: verdict = %+v, want blocked 451", i, verdict)
			}
		} else if verdict.Kind != VerdictPassthrough {
			t.Errorf("request %d: verdict = %+v, want passthrough", i, verdict)
		}
	}
}

func TestRunParallel_StoreUpdateDuringTraffic(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockProfileYAML("hot-swap", "/hot", 451, "blocked-hot", -1))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			h.Fixture.ApplyYAML(blockProfileYAML("hot-swap", "/hot", 451, "blocked-hot", i%1000))
		}
	}()
	verdicts := h.RunParallel(t, 32, func(int) *RequestBuilder {
		return testRequest("/hot")
	})
	<-done

	// Every request must observe some consistent snapshot: always blocked.
	for i, verdict := range verdicts {
		if verdict.Err != nil {
			t.Fatalf("request %d: Process error: %v", i, verdict.Err)
		}
		if verdict.Kind != VerdictBlocked {
			t.Errorf("request %d: verdict = %s, want blocked", i, verdict.Kind)
		}
	}
}

func TestAudit_BufferedAbsenceAfterDrain(t *testing.T) {
	receiver := NewAuditReceiver(t)
	wiring := WireAudit(t, AuditOptions{Mode: AuditBuffered})
	h := New(t, Options{AuditRouter: wiring.Router})
	h.Fixture.ApplyYAML(auditProfileYAML(receiver.URL("")))

	present := "drain-present-marker"
	absent := "drain-absent-marker"
	h.Run(t, testRequest("/audited").Header("x-audit-marker", present)).
		RequireBlocked(t, 451)
	h.Run(t, testRequest("/not-audited").Header("x-audit-marker", absent)).
		RequirePassthrough(t)

	// The drain barrier makes the absence assertion sound without sleeping.
	wiring.Drain(t)
	receiver.WaitFor(t, present, time.Second)
	receiver.AssertAbsent(t, absent)
}
