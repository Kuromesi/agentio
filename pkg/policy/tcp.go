// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/netip"
	"slices"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

// CompileTCPRules validates and normalizes the inline gateway destination chain.
func CompileTCPRules(rules []agents.TCPRule) (*securityv1.TCPPolicy, error) {
	result := &securityv1.TCPPolicy{}
	for _, rule := range rules {
		out := &securityv1.TCPRule{Name: rule.Name}
		switch rule.Action {
		case "allow":
			out.Action = securityv1.TCPAction_TCP_ACTION_ALLOW
		case "deny":
			out.Action = securityv1.TCPAction_TCP_ACTION_DENY
		}
		for _, match := range rule.Match {
			clause := &securityv1.TCPMatch{Cidrs: slices.Clone(match.CIDRs)}
			for _, port := range match.Ports {
				clause.Ports = append(clause.Ports, uint32(port))
			}
			out.Match = append(out.Match, clause)
		}
		result.Rules = append(result.Rules, out)
	}
	if err := NormalizeTCPPolicy(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NormalizeTCPPolicy validates an unpublished policy and canonicalizes its CIDRs.
func NormalizeTCPPolicy(value *securityv1.TCPPolicy) error {
	names := make(map[string]bool, len(value.GetRules()))
	for _, rule := range value.GetRules() {
		if rule.GetName() == "" || names[rule.GetName()] {
			return fmt.Errorf("tcpRules: empty or duplicate name %q", rule.GetName())
		}
		names[rule.Name] = true
		if rule.Action != securityv1.TCPAction_TCP_ACTION_ALLOW && rule.Action != securityv1.TCPAction_TCP_ACTION_DENY {
			return fmt.Errorf("tcpRules %q: invalid action %v", rule.Name, rule.Action)
		}
		if len(rule.Match) == 0 {
			return fmt.Errorf("tcpRules %q: match is required", rule.Name)
		}
		for _, match := range rule.Match {
			if match == nil {
				return fmt.Errorf("tcpRules %q: match is required", rule.Name)
			}
			for i, raw := range match.Cidrs {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.Addr().Is4In6() {
					return fmt.Errorf("tcpRules %q: invalid or IPv4-mapped CIDR %q", rule.Name, raw)
				}
				match.Cidrs[i] = prefix.Masked().String()
			}
			for _, port := range match.Ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("tcpRules %q: invalid port %d", rule.Name, port)
				}
			}
		}
	}
	return nil
}

// MatchTCPRules evaluates already validated rules; callers concatenate profiles
// before applying the default allow so an unmatched profile cannot end the chain.
func MatchTCPRules(rules []*securityv1.TCPRule, target netip.AddrPort) (allowed bool, index int) {
	for i, rule := range rules {
		for _, match := range rule.Match {
			if len(match.Ports) > 0 && !slices.Contains(match.Ports, uint32(target.Port())) {
				continue
			}
			addressMatches := len(match.Cidrs) == 0
			for _, cidr := range match.Cidrs {
				if netip.MustParsePrefix(cidr).Contains(target.Addr().Unmap()) {
					addressMatches = true
					break
				}
			}
			if addressMatches {
				return rule.Action == securityv1.TCPAction_TCP_ACTION_ALLOW, i
			}
		}
	}
	return true, -1
}
