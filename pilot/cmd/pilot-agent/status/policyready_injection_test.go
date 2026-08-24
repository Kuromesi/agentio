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

package status

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"istio.io/istio/pilot/cmd/pilot-agent/status/policyready"
)

func hasPolicyReadyProbe(s *Server) bool {
	for _, probe := range s.ready {
		if _, ok := probe.(*policyready.Probe); ok {
			return true
		}
	}
	return false
}

// The probe must only be wired up when the gateway policy store extension is
// actually configured. A proxy without it never publishes
// policy_store.initial_sync_ready, so an unconditional probe would hold it
// unready on every start.
func TestPolicyReadyProbeInjection(t *testing.T) {
	cases := []struct {
		name        string
		policyStore bool
		noEnvoy     bool
		want        bool
	}{
		{name: "enabled", policyStore: true, want: true},
		{name: "disabled", policyStore: false, want: false},
		{name: "enabled but envoy disabled", policyStore: true, noEnvoy: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewServer(Options{
				PolicyStore:        tc.policyStore,
				NoEnvoy:            tc.noEnvoy,
				AdminPort:          15000,
				PrometheusRegistry: prometheus.NewRegistry(),
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			if got := hasPolicyReadyProbe(server); got != tc.want {
				t.Fatalf("policyready probe present = %v, want %v", got, tc.want)
			}
		})
	}
}
