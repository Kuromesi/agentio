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
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// These immutable views contain only what the CONNECT policy handler consumes.
type workloadView struct {
	uid      string
	policies []*extensions.SniTrafficPolicy
}

type sandboxView struct {
	uid         string
	workloadUID string
	policies    []*extensions.SniTrafficPolicy
}

// Watches defines Porter's projections and subscription lifetime. Deleted
// resources are no longer needed; the next CONNECT can demand them again.
func Watches() []xdsclient.Watch {
	return []xdsclient.Watch{
		{
			TypeURL:   model.WorkloadType,
			Transform: transformWorkload,
			OnDelete:  func(string) xdsclient.DeleteAction { return xdsclient.ReleaseSubscription },
		},
		{
			TypeURL:   model.SandboxType,
			Transform: transformSandbox,
			OnDelete:  func(string) xdsclient.DeleteAction { return xdsclient.ReleaseSubscription },
		},
	}
}

func transformWorkload(value *anypb.Any) (any, error) {
	w := &workload.Workload{}
	if err := value.UnmarshalTo(w); err != nil {
		return nil, err
	}
	values := make([]*anypb.Any, 0, len(w.GetExtensions()))
	for _, extension := range w.GetExtensions() {
		values = append(values, extension.GetConfig())
	}
	policies, err := decodePolicies(values)
	if err != nil {
		return nil, err
	}
	return &workloadView{uid: w.GetUid(), policies: policies}, nil
}

func transformSandbox(value *anypb.Any) (any, error) {
	s := &sandbox.Sandbox{}
	if err := value.UnmarshalTo(s); err != nil {
		return nil, err
	}
	policies, err := decodePolicies(s.GetExtensions())
	if err != nil {
		return nil, err
	}
	return &sandboxView{uid: s.GetUid(), workloadUID: s.GetAttester().GetWorkloadUid(), policies: policies}, nil
}

func decodePolicies(values []*anypb.Any) ([]*extensions.SniTrafficPolicy, error) {
	var policies []*extensions.SniTrafficPolicy
	for _, value := range values {
		if !value.MessageIs(&extensions.SniTrafficPolicy{}) {
			continue
		}
		policy := &extensions.SniTrafficPolicy{}
		if err := value.UnmarshalTo(policy); err != nil {
			return nil, err
		}
		for _, rule := range policy.GetRules() {
			switch rule.GetAction() {
			case extensions.SniAction_SNI_ACTION_TLS_TERMINATION,
				extensions.SniAction_SNI_ACTION_PASSTHROUGH,
				extensions.SniAction_SNI_ACTION_DENY:
			default:
				return nil, fmt.Errorf("unsupported SNI action %d", rule.GetAction())
			}
		}
		policies = append(policies, policy)
	}
	return policies, nil
}
