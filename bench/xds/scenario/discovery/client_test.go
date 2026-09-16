// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"testing"

	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/openkruise/agentio/bench/xds/scenario"
)

func TestReadinessIsPerStreamAndRequiresEveryType(t *testing.T) {
	f, err := New(json.RawMessage(`{"types":["one","two"]}`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := f.New(), f.New()
	for _, step := range []struct {
		client scenario.Client
		typ    string
		ready  bool
	}{
		{a, "one", false}, {b, "two", false}, {a, "unsubscribed", false}, {a, "two", true}, {b, "one", true},
	} {
		got, err := step.client.Observe(&ads.DeltaDiscoveryResponse{TypeUrl: step.typ}, nil)
		if err != nil || got.Ready != step.ready || got.Reply != scenario.ACK {
			t.Fatalf("observation=%+v err=%v", got, err)
		}
	}
}
