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
package wiring

import (
	"context"
	"testing"

	"istio.io/istio/extensions/epe/pkg/filters/httpcallout"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/test"
)

// The action order inside one rule is a load-bearing, machine-checked
// contract. Rules themselves are evaluated in policy order by the engine.
func TestBuildFiltersOrderIsExplicit(t *testing.T) {
	regs, err := BuildFilters(Deps{Kube: kube.NewFakeClient(), Stop: test.NewStop(t)})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	want := []string{"bypass", "block", "mcpacl", "headermutation", "httpcallout", "tokentransform"}
	if len(regs) != len(want) {
		t.Fatalf("got %d registrations, want %d", len(regs), len(want))
	}
	for i, reg := range regs {
		if reg.Name != want[i] {
			t.Errorf("position %d = %q, want %q", i, reg.Name, want[i])
		}
	}
}

// stubCalloutClient stands in for an in-process endpoint. It is a struct{} so
// interface values holding it stay comparable.
type stubCalloutClient struct{}

func (stubCalloutClient) Call(context.Context, httpcallout.Config, httpcallout.Invocation) (httpcallout.Decision, error) {
	return httpcallout.Decision{}, nil
}

// CalloutClient is the seam a scenario test uses to aim the callout filter at an
// in-process endpoint, so the injection itself has to hold: a supplied client
// must be used as-is, and its absence must still yield a usable client rather
// than a nil one the filter would reject at request time.
func TestCalloutClientForPrefersTheSuppliedClient(t *testing.T) {
	supplied := stubCalloutClient{}
	if got := calloutClientFor(Deps{CalloutClient: supplied}); got != httpcallout.Client(supplied) {
		t.Errorf("calloutClientFor(supplied) = %#v, want the supplied client", got)
	}
	if got := calloutClientFor(Deps{}); got == nil {
		t.Error("calloutClientFor(zero Deps) = nil, want the default shared HTTP client")
	}
}
