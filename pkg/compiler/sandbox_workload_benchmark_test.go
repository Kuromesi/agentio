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
	"fmt"
	"testing"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// BenchmarkSandboxCompatibilityProjection includes legacy encoding and resource
// hashing. Inputs are already compiled; no API decoding, selector matching, DNS,
// or per-client ADS work belongs in this measurement.
func BenchmarkSandboxCompatibilityProjection(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			stop := make(chan struct{})
			b.Cleanup(func() { close(stop) })
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			workload := testWorkload("demo", "client", "10.0.0.1")
			sandbox := model.Sandbox{UID: "actor", Namespace: "demo", Attester: &model.Attester{WorkloadUID: workload.UID}}
			rules := make([]*securityv1.TrafficPolicy_Rule, count)
			for i := range count {
				rules[i] = &securityv1.TrafficPolicy_Rule{Match: &securityv1.TrafficPolicy_Match{
					DestinationIps: []*securityv1.TrafficPolicy_Address{{Address: []byte{10, byte(i >> 8), byte(i), 0}, Length: 24}},
				}}
			}
			compiled := policy.CompiledTrafficPolicy{CompiledPolicy: policy.CompiledPolicy[*securityv1.TrafficPolicy]{
				Name: "trafficPolicies/shared", Policy: &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{Rules: rules}},
			}}
			policies := policyCollections{
				trafficPolicies: krt.NewStaticCollection(nil, []policy.CompiledTrafficPolicy{compiled}, opts...),
				sniPolicies:     krt.NewStaticCollection[policy.CompiledSNIPolicy](nil, nil, opts...),
				policyBindings: krt.NewStaticCollection(nil, []policy.Bindings{{
					TargetKind: policy.PolicyTargetSandbox, TargetUID: sandbox.UID,
					Groups: []policy.BindingGroup{{Kind: policy.PolicyKindTrafficPolicy, Names: []string{compiled.Name}}},
				}}, opts...),
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				projection, err := sandboxAsWorkload(krt.TestingDummyContext{}, workload, sandbox, policies)
				if err != nil || len(projection.Resources) != 2 {
					b.Fatalf("projection: %v", err)
				}
			}
		})
	}
}
