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

package policy

import (
	"fmt"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
)

// CompileEgressRouting adapts already selected and resolved legacy policies.
// DENY cannot be dropped or translated without changing cross-policy precedence.
func CompileEgressRouting(effective *extensionsv1.EgressPolicies) (*sandboxv1.EgressRouting, error) {
	if effective == nil {
		return nil, nil
	}
	routing := &sandboxv1.EgressRouting{}
	for index, source := range effective.GetEgressPolicies() {
		if source == nil {
			return nil, fmt.Errorf("egress route %d is nil", index)
		}
		route := &sandboxv1.EgressRouting_Route{
			MatchCidrs: append([]string(nil), source.GetMatchCidrs()...),
			MatchPorts: append([]string(nil), source.GetMatchPorts()...),
		}
		switch source.GetPolicy() {
		case extensionsv1.EgressPolicyAction_PASSTHROUGH:
			route.Action = sandboxv1.EgressRouting_PASSTHROUGH
		case extensionsv1.EgressPolicyAction_GATEWAY:
			if source.GetGateway() == nil {
				return nil, fmt.Errorf("egress route %d requires a gateway", index)
			}
			route.Action = sandboxv1.EgressRouting_GATEWAY
			route.Gateway = &sandboxv1.EgressRouting_GatewayAddress{
				Service: source.GetGateway().GetService(),
				Port:    source.GetGateway().GetPort(),
			}
		case extensionsv1.EgressPolicyAction_DENY:
			return nil, fmt.Errorf("egress policy %d uses DENY; move access control to TrafficPolicy before using EgressRouting", index)
		default:
			return nil, fmt.Errorf("egress policy %d has unknown action %d", index, source.GetPolicy())
		}
		routing.Routes = append(routing.Routes, route)
	}
	return routing, nil
}
