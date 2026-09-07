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

package agentio

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func TestInlineSNIPolicyTracksRulesOrderAndRemoval(t *testing.T) {
	opts := krttest.Options(t)
	one := sniTestWorkload("one", "ns", map[string]string{"app": "one"})
	two := sniTestWorkload("two", "ns", map[string]string{"app": "two"})
	first := sniBindablePolicy("ns", "first", 20, map[string]string{"app": "one"})
	second := sniBindablePolicy("ns", "second", 10, map[string]string{"app": "one"})
	other := sniBindablePolicy("ns", "other", 10, map[string]string{"app": "two"})
	first.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_DENY, "first.example.com")}}
	second.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_PASSTHROUGH, "second.example.com")}}
	policies := krt.NewStaticCollection(nil, []BindablePolicy{first, second, other}, opts.WithName("policies")...)
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{one, two}, opts.WithName("workloads")...)
	controller := &Controller{bindablePolicies: policies, policyAttachments: newPolicyAttachmentsCollection(policies, opts)}
	inline := controller.BuildWorkloadSNIPoliciesCollection(workloads, opts)
	inline.WaitUntilSynced(test.NewStop(t))
	check := func(want ...*extensions.SniRule) {
		t.Helper()
		retry.UntilSuccessOrFail(t, func() error {
			got := inline.GetKey(one.ResourceName())
			if got == nil || !proto.Equal(got.Policy, &extensions.SniTrafficPolicy{Rules: want}) {
				return fmt.Errorf("got %v, want rules %v", got, want)
			}
			return nil
		})
	}
	check(first.Resource.(*extensions.SniTrafficPolicy).Rules[0], second.Resource.(*extensions.SniTrafficPolicy).Rules[0])
	untouched := inline.GetKey(two.ResourceName()).Policy
	changed := first
	changed.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "changed.example.com")}}
	policies.UpdateObject(changed)
	check(changed.Resource.(*extensions.SniTrafficPolicy).Rules[0], second.Resource.(*extensions.SniTrafficPolicy).Rules[0])
	if inline.GetKey(two.ResourceName()).Policy != untouched {
		t.Fatal("unrelated workload was rebuilt")
	}
	// Source removal must remove only its rules, then remove the extension entirely.
	policies.DeleteObject(first.ResourceName())
	check(second.Resource.(*extensions.SniTrafficPolicy).Rules[0])
	policies.DeleteObject(second.ResourceName())
	retry.UntilSuccessOrFail(t, func() error {
		if inline.GetKey(one.ResourceName()) != nil {
			return fmt.Errorf("inline policy survived source removal")
		}
		return nil
	})
}

func TestInlineSNIPolicyRecoversMissingPayload(t *testing.T) {
	for _, state := range []string{"absent", "nil", "wrong type"} {
		t.Run(state, func(t *testing.T) {
			opts := krttest.Options(t)
			first := sniBindablePolicy("ns", "first", 20, nil)
			second := sniBindablePolicy("ns", "second", 10, nil)
			first.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_DENY, "first.example.com")}}
			second.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "second.example.com")}}
			initial := []BindablePolicy{first}
			unresolved := second
			switch state {
			case "nil":
				unresolved.Resource = (*extensions.SniTrafficPolicy)(nil)
				initial = append(initial, unresolved)
			case "wrong type":
				unresolved.Resource = &extensions.PolicyReference{}
				initial = append(initial, unresolved)
			}
			policies := krt.NewStaticCollection(nil, initial, opts.WithName("policies")...)
			// Freeze the reference projection after selection but before the second
			// payload is available. Restoring the payload must suffice for recovery.
			refs := krt.NewStaticCollection(nil, []WorkloadPolicyReferences{{
				Name: "workload",
				References: []*extensions.PolicyReference{{
					TypeUrl: xdsmodel.SniTrafficPolicyType, ResourceNames: []string{first.Name, second.Name},
				}},
			}}, opts.WithName("references")...)
			inline := newWorkloadSNIPoliciesCollection(refs, policies, opts)
			inline.WaitUntilSynced(test.NewStop(t))
			if got := inline.GetKey("workload"); got != nil {
				t.Fatalf("published a partial policy: %v", got.Policy)
			}
			check := func() {
				t.Helper()
				want := &extensions.SniTrafficPolicy{Rules: append(
					append([]*extensions.SniRule{}, first.Resource.(*extensions.SniTrafficPolicy).Rules...),
					second.Resource.(*extensions.SniTrafficPolicy).Rules...,
				)}
				retry.UntilSuccessOrFail(t, func() error {
					got := inline.GetKey("workload")
					if got == nil || !proto.Equal(got.Policy, want) {
						return fmt.Errorf("got %v, want %v", got, want)
					}
					return nil
				})
			}
			policies.UpdateObject(second)
			check()
			second.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_PASSTHROUGH, "changed.example.com")}}
			policies.UpdateObject(second)
			check()
		})
	}
}
