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
// with bypass's own (empty) payload. Bypass is wire-invisible — the request
// continues unmodified — so the assertion targets what it actually owns: the
// stream resolves as bypassed rather than passthrough, which is what ends the
// walk and skips every remaining action.
package bypass_test

import (
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/bypass"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

func TestScenario_BypassResolvesStreamAsBypassed(t *testing.T) {
	h := enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: bypass.Definition(),
		Payload:    `{}`,
	})
	verdict := h.Run(t, enginetest.NewRequest("GET", "api.example.com", "/v1").
		Peer("test-ns", "sandbox-a", map[string]string{"app": "sandbox"}))
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	if verdict.Kind != enginetest.VerdictPassthrough {
		t.Errorf("Kind = %s, want passthrough on the wire", verdict.Kind)
	}
	if len(verdict.RequestHeaderOps) != 0 {
		t.Errorf("RequestHeaderOps = %+v, want none", verdict.RequestHeaderOps)
	}
	if verdict.Info == nil || verdict.Info.Outcome != filter.DispositionBypassed {
		t.Errorf("Outcome = %v, want bypassed", verdict.Info)
	}
}
