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
// with block's own payload schema — no policy CRD involved. They pin the one
// wire-visible behavior block owns: the immediate response that reaches
// Envoy, including the filter-side status defaulting for payloads that never
// passed API-server defaulting.
package block_test

import (
	"testing"

	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

func blockRequest() *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "evil.example.com", "/exfil").
		Peer("test-ns", "sandbox-a", map[string]string{"app": "sandbox"})
}

func TestScenario_BlockReturnsConfiguredImmediateResponse(t *testing.T) {
	h := enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: block.Definition(),
		Payload:    `{"statusCode":451,"body":"denied by policy"}`,
	})
	verdict := h.Run(t, blockRequest())
	verdict.RequireBlockedBody(t, 451, "denied by policy")
	if verdict.Err != nil {
		t.Fatalf("a block verdict must not be a processing error: %v", verdict.Err)
	}
}

func TestScenario_BlockDefaultsTo403(t *testing.T) {
	h := enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: block.Definition(),
		Payload:    `{}`,
	})
	h.Run(t, blockRequest()).RequireBlocked(t, 403)
}
