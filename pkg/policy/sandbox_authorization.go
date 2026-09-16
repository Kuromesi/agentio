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
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

// SandboxAsAuthorizations projects an already ordered policy chain for an exact
// Workload reference. It does not resolve peers or match selectors again.
// A nil entry is an unavailable referenced policy, a deny barrier in both directions.
func SandboxAsAuthorizations(name, namespace string, policies []*securityv1.TrafficPolicy) ([]CompiledAuthorization, error) {
	result := make([]CompiledAuthorization, 0, 2)
	for _, direction := range []struct {
		suffix string
		mode   extensionsv1.TrafficPolicyMode
		rules  func(*securityv1.TrafficPolicy) *securityv1.TrafficPolicy_RuleSet
	}{
		{"egress", extensionsv1.TrafficPolicyMode_CLIENT, (*securityv1.TrafficPolicy).GetEgress},
		{"ingress", extensionsv1.TrafficPolicyMode_SERVER, (*securityv1.TrafficPolicy).GetIngress},
	} {
		// User priorities are nonnegative. This whole chain must precede legacy
		// namespace/global policies that may also be cached by a shared proxy.
		extension, err := newTrafficPolicyExtension(-1, direction.mode)
		if err != nil {
			return nil, err
		}
		authorization := &securityv1.Authorization{
			Name: name + "-" + direction.suffix, Namespace: namespace,
			Scope: securityv1.Scope_WORKLOAD_SELECTOR, Action: securityv1.Action_ALLOW,
			AuthExtensions: []*securityv1.Extension{extension},
		}
		configured := false
		for _, p := range policies {
			if p == nil {
				configured = true
				break
			}
			if rules := direction.rules(p); rules != nil {
				configured = true
				for _, rule := range rules.Rules {
					authorization.Groups = append(authorization.Groups, sandboxAuthorizationGroup(rule))
				}
			}
		}
		// Terminal fallback prevents unrelated legacy policies from changing
		// Sandbox semantics: configured direction => deny; absent => allow.
		authorization.Groups = append(authorization.Groups, sandboxDefaultGroup(configured))
		result = append(result, CompiledAuthorization{
			Name: namespace + "/" + authorization.Name, Policy: authorization,
		})
	}
	return result, nil
}

func sandboxDefaultGroup(deny bool) *securityv1.Group {
	match := &securityv1.Match{}
	addresses := []*securityv1.Address{{Address: make([]byte, 4)}, {Address: make([]byte, 16)}}
	if deny {
		match.NotDestinationIps = addresses
	} else {
		match.DestinationIps = addresses
	}
	return &securityv1.Group{Rules: []*securityv1.Rules{{Matches: []*securityv1.Match{match}}}}
}

// Normalize unconstrained matches for both legacy TCP RBAC and the firewall.
// The firewall drops empty groups; negative groups also need a not_* field.
func sandboxAuthorizationGroup(rule *securityv1.TrafficPolicy_Rule) *securityv1.Group {
	for _, port := range rule.GetMatch().GetPorts() {
		if port.Protocol == securityv1.TrafficPolicy_ALL && port.Port == nil && port.EndPort == nil {
			// Port alternatives are ORed: one unconstrained entry removes the
			// entire port constraint, including any constrained siblings.
			rule = &securityv1.TrafficPolicy_Rule{Action: rule.Action, Match: &securityv1.TrafficPolicy_Match{
				SourceIps: rule.Match.SourceIps, DestinationIps: rule.Match.DestinationIps,
			}}
			break
		}
	}
	group := asAuthorizationGroup(rule)
	if len(group.Rules) == 0 {
		return sandboxDefaultGroup(rule.Action == securityv1.TrafficPolicy_DENY)
	}
	return group
}
