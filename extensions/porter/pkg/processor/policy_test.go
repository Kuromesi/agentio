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

package processor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

const testUID = "Kubernetes//Pod/demo/client"

type memorySource struct {
	values map[string]*anypb.Any
	calls  []string
	err    error
}

func (s *memorySource) Demand(_ context.Context, typ, name string) (*xdsclient.Resource, error) {
	s.calls = append(s.calls, typ+"/"+name)
	if s.err != nil {
		return nil, s.err
	}
	value := s.values[typ+"/"+name]
	if value == nil {
		return nil, xdsclient.ErrNotFound
	}
	for _, watch := range Watches() {
		if watch.TypeURL == typ {
			view, err := watch.Transform(value)
			return &xdsclient.Resource{Value: view}, err
		}
	}
	return nil, errors.New("unexpected resource type")
}
func pack(t *testing.T, value proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(value)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func sniPolicy(t *testing.T, pattern string, action extensions.SniAction) *anypb.Any {
	return pack(
		t,
		&extensions.SniTrafficPolicy{
			Rules: []*extensions.SniRule{{Match: &extensions.SniMatch{Sni: []string{pattern}}, Action: action}},
		},
	)
}
func sourceWorkload(t *testing.T, policy *anypb.Any) *anypb.Any {
	w := &workload.Workload{Uid: testUID, Name: "client", Namespace: "demo"}
	if policy != nil {
		w.Extensions = []*workload.Extension{{Name: "sni", Config: policy}}
	}
	return pack(t, w)
}
func action(result Result) string {
	sni, _ := result.Metadata["sni"].(map[string]any)
	policy, _ := sni["policy"].(map[string]any)
	rules, _ := policy["rules"].([]any)
	if len(rules) == 0 {
		return "passthrough"
	}
	rule := rules[0].(map[string]any)
	return map[string]string{"SNI_ACTION_TLS_TERMINATION": "terminate", "SNI_ACTION_PASSTHROUGH": "passthrough", "SNI_ACTION_DENY": "deny"}[rule["action"].(string)]
}
func TestReturnsOrderedRulesWithoutEvaluatingSNI(t *testing.T) {
	policy := &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
		{Match: &extensions.SniMatch{Sni: []string{"deny.example"}}, Action: extensions.SniAction_SNI_ACTION_DENY},
		{Match: &extensions.SniMatch{Sni: []string{"*"}}, Action: extensions.SniAction_SNI_ACTION_TLS_TERMINATION},
	}}
	source := &memorySource{
		values: map[string]*anypb.Any{model.WorkloadType + "/" + testUID: sourceWorkload(t, pack(t, policy))},
	}
	result, err := NewPolicyHandler(
		source,
		"Kubernetes",
	).Handle(t.Context(), Request{Source: Source{Workload: WorkloadIdentity{Name: "client", Namespace: "demo"}}})
	if err != nil || result.DenyStatus != 0 {
		t.Fatalf("policy resolution: %+v %v", result, err)
	}
	fields := result.Metadata["sni"].(map[string]any)["policy"]
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(extensions.SniTrafficPolicy)
	if err := protojson.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(policy, decoded) {
		t.Fatalf("ordered policy changed: %v", decoded)
	}
	if result.Metadata["workload"].(map[string]any)["name"] != "client" {
		t.Fatal("resolved identity absent")
	}
}
func TestSandboxBindingAndMissingResources(t *testing.T) {
	for _, tc := range []struct {
		name            string
		host            string
		missingWorkload bool
		missingSandbox  bool
		want            string
		deny            bool
	}{
		{name: "owned", host: testUID, want: "terminate"},
		{name: "wrong host", host: "another", deny: true},
		{name: "unassigned", deny: true},
		{name: "deleted sandbox", missingSandbox: true, deny: true},
		{name: "deleted workload", missingWorkload: true, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]*anypb.Any{}
			if !tc.missingWorkload {
				values[model.WorkloadType+"/"+testUID] = sourceWorkload(t, nil)
			}
			if !tc.missingSandbox {
				values[model.SandboxType+"/kruise:one"] = pack(
					t,
					&sandbox.Sandbox{
						Uid:      "kruise:one",
						Attester: &sandbox.Sandbox_Attester{WorkloadUid: tc.host},
						Extensions: []*anypb.Any{
							sniPolicy(t, "*.example.com", extensions.SniAction_SNI_ACTION_TLS_TERMINATION),
						},
					},
				)
			}
			got, err := NewPolicyHandler(
				&memorySource{values: values},
				"Kubernetes",
			).Handle(
				t.Context(),
				Request{
					Source: Source{
						Workload:  WorkloadIdentity{Name: "client", Namespace: "demo"},
						SandboxID: "kruise:one",
					},
				},
			)
			if err != nil || (!tc.deny && action(got) != tc.want) || (got.DenyStatus != 0) != tc.deny {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}
func TestMissingIdentityAndDemandFailure(t *testing.T) {
	source := &memorySource{err: errors.New("ADS unavailable")}
	handler := NewPolicyHandler(source, "Kubernetes")
	got, err := handler.Handle(t.Context(), Request{})
	if err != nil || got.DenyStatus != envoytype.StatusCode_Forbidden || len(source.calls) != 0 {
		t.Fatalf("missing identity: %+v %v", got, err)
	}
	_, err = handler.Handle(
		t.Context(),
		Request{
			Source: Source{Workload: WorkloadIdentity{Name: "client", Namespace: "demo"}},
		},
	)
	if !errors.Is(err, source.err) {
		t.Fatalf("demand failure swallowed: %v", err)
	}
}
