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

package compiler

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// BenchmarkDNSFlipRecomputesAllSandboxes times the propagation wave after one egress hostname's DNS result changes.
func BenchmarkDNSFlipRecomputesAllSandboxes(b *testing.B) {
	count := 10_000
	if override := os.Getenv("DNS_FLIP_SANDBOXES"); override != "" {
		parsed, err := strconv.Atoi(override)
		if err != nil || parsed <= 0 {
			b.Fatalf("invalid DNS_FLIP_SANDBOXES=%q", override)
		}
		count = parsed
	}
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	dnsResults := krt.NewStaticCollection[dnsBenchmarkResult](nil,
		[]dnsBenchmarkResult{{host: "api.example.com", address: netip.MustParseAddr("10.1.0.1")}}, options...)
	compiler := dnsScaleCompiler(b, count, dnsResults, stop, options, nil)
	waitSynced(b, compiler)

	var addressUpdates atomic.Uint64
	registration := compiler.Resources().RegisterBatch(func(events []krt.Event[model.Resource]) {
		for _, event := range events {
			if event.Latest().Key.TypeURL == model.AddressType {
				addressUpdates.Add(1)
			}
		}
	}, false)
	b.Cleanup(registration.UnregisterHandler)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		// The address must differ from the initial 10.1.0.1 and from every
		// previous iteration, or the update is suppressed as a no-op and the
		// wave never starts.
		address := netip.AddrFrom4([4]byte{10, 1, 1, byte(iteration % 256)})
		started := time.Now()
		dnsResults.ConditionalUpdateObject(dnsBenchmarkResult{host: "api.example.com", address: address})
		target := uint64(iteration+1) * uint64(count)
		waitForAddressUpdates(b, &addressUpdates, target)
		b.ReportMetric(float64(time.Since(started).Microseconds()), "wave_us/op")
	}
}

// TestDNSFlipUsesNarrowWorkloadConfigurationDependency protects the production
// graph from wiring Workloads directly to the full configuration as well as to
// the compiled egress policy produced by that configuration.
func TestDNSFlipUsesNarrowWorkloadConfigurationDependency(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	dnsResults := krt.NewStaticCollection[dnsBenchmarkResult](nil,
		[]dnsBenchmarkResult{{host: "api.example.com", address: netip.MustParseAddr("10.1.0.1")}}, options...)
	debugger := new(krt.DebugHandler)
	compiler := dnsScaleCompiler(t, 1, dnsResults, stop, options, debugger)
	waitSynced(t, compiler)

	debugDump, err := json.Marshal(debugger)
	if err != nil {
		t.Fatalf("marshal KRT debug collections: %v", err)
	}
	var collections []struct {
		Name  string `json:"name"`
		State struct {
			Inputs map[string]struct {
				Dependencies []string `json:"dependencies"`
			} `json:"inputs"`
		} `json:"state"`
	}
	if err := json.Unmarshal(debugDump, &collections); err != nil {
		t.Fatalf("unmarshal KRT debug collections: %v", err)
	}
	var dependencies []string
	for _, collection := range collections {
		if collection.Name == "workload-resources" {
			dependencies = collection.State.Inputs["cluster//Pod/demo/sandbox-0"].Dependencies
			break
		}
	}
	if !slices.Contains(dependencies, "workload-metadata-configuration") {
		t.Fatalf("workload dependencies = %v, want workload-metadata-configuration", dependencies)
	}
	if slices.Contains(dependencies, "configuration") {
		t.Fatalf("workload dependencies = %v, must not include full configuration", dependencies)
	}

	var addressUpdates atomic.Uint64
	registration := compiler.Resources().RegisterBatch(func(events []krt.Event[model.Resource]) {
		for _, event := range events {
			if event.Latest().Key.TypeURL == model.AddressType {
				addressUpdates.Add(1)
			}
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	dnsResults.ConditionalUpdateObject(dnsBenchmarkResult{
		host: "api.example.com", address: netip.MustParseAddr("10.1.0.2"),
	})
	eventually(t, func() bool { return addressUpdates.Load() == 1 }, "DNS update published one Address update")
}

func waitForAddressUpdates(t testing.TB, updates *atomic.Uint64, target uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for updates.Load() < target {
		if time.Now().After(deadline) {
			t.Fatalf("Address update wave did not complete: %d < %d", updates.Load(), target)
		}
		time.Sleep(500 * time.Microsecond)
	}
}

type dnsBenchmarkResult struct {
	host    string
	address netip.Addr
}

func (r dnsBenchmarkResult) ResourceName() string { return r.host }

func dnsScaleCompiler(t testing.TB, count int, dnsResults krt.Collection[dnsBenchmarkResult],
	stop <-chan struct{}, options []krt.CollectionOption, debugger *krt.DebugHandler,
) *Compiler {
	t.Helper()
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	for index := range count {
		workload := testWDSWorkload(fmt.Sprintf("sandbox-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
		workload.Labels = map[string]string{"app": "sandbox"}
		workloads.ConditionalUpdateObject(workload)
	}
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
		Name: "egress-default", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}},
			}}},
		},
	}}, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	// The egress policy's match hostname is what pins the configuration
	// singleton to the DNS results collection.
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress-0"}},
			EgressPolicies: []*extensionsv1.EgressPolicy{{MatchHosts: []string{"api.example.com"}}},
		},
	}}, options...)

	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	inputs.Resolve = func(ctx krt.HandlerContext, host string) []netip.Addr {
		if result := krt.FetchOne(ctx, dnsResults, krt.FilterKey(host)); result != nil {
			return []netip.Addr{result.address}
		}
		return nil
	}
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", debugger))
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}
