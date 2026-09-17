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
