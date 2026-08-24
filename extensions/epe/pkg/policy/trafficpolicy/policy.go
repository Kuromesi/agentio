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

// Package trafficpolicy compiles TrafficPolicy egress rules into a small
// CONNECT-time authorizer. It deliberately evaluates only information present
// on the CONNECT request: the authenticated caller labels and destination
// host/port.
package trafficpolicy

import (
	"fmt"
	"net/netip"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type peerKind uint8

const (
	peerUnsupported peerKind = iota
	peerCIDR
	peerFQDN
)

type peer struct {
	kind   peerKind
	prefix netip.Prefix
	fqdn   string
}

type port struct {
	protocol string
	start    int32
	end      int32
}

type rule struct {
	action agentsv1alpha1.RuleAction
	to     []peer
	ports  []port
}

// Policy is an immutable compiled TrafficPolicy or GlobalTrafficPolicy.
type Policy struct {
	Name              string
	Namespace         string
	Global            bool
	Priority          int32
	CreationTimestamp metav1.Time
	Version           string
	Selector          labels.Selector
	rules             []rule
	CompileError      string
}

// ResourceName implements krt.ResourceNamer. Scope prefixes prevent a global
// policy from colliding with a namespaced policy.
func (p Policy) ResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Namespace + "/" + p.Name
}

func (p Policy) displayName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return p.Namespace + "/" + p.Name
}

func compilePolicy(obj metav1.Object, spec *agentsv1alpha1.TrafficPolicySpec, global bool) (*Policy, error) {
	selector, err := metav1.LabelSelectorAsSelector(&spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("selector: %w", err)
	}
	p := &Policy{
		Name:              obj.GetName(),
		Namespace:         obj.GetNamespace(),
		Global:            global,
		Priority:          spec.Priority,
		CreationTimestamp: obj.GetCreationTimestamp(),
		Version:           obj.GetResourceVersion(),
		Selector:          selector,
	}
	if spec.Egress == nil {
		return p, nil
	}
	p.rules = make([]rule, 0, len(spec.Egress.Rules))
	for i := range spec.Egress.Rules {
		compiled, err := compileRule(spec.Egress.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("egress rule %d: %w", i, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

func invalidPolicy(obj metav1.Object, spec *agentsv1alpha1.TrafficPolicySpec, global bool, err error) *Policy {
	message := "invalid traffic policy"
	if err != nil {
		message = err.Error()
	}
	return &Policy{
		Name:              obj.GetName(),
		Namespace:         obj.GetNamespace(),
		Global:            global,
		Priority:          spec.Priority,
		CreationTimestamp: obj.GetCreationTimestamp(),
		Version:           obj.GetResourceVersion(),
		CompileError:      message,
	}
}

func compileRule(in agentsv1alpha1.TrafficPolicyRule) (rule, error) {
	if in.Action != agentsv1alpha1.RuleActionAllow && in.Action != agentsv1alpha1.RuleActionReject {
		return rule{}, fmt.Errorf("unsupported action %q", in.Action)
	}
	out := rule{action: in.Action}
	for _, raw := range in.To {
		compiled, err := compilePeer(raw)
		if err != nil {
			return rule{}, err
		}
		out.to = append(out.to, compiled)
	}
	for _, raw := range in.Ports {
		compiled, err := compilePort(raw)
		if err != nil {
			return rule{}, err
		}
		out.ports = append(out.ports, compiled)
	}
	return out, nil
}

func compilePeer(in agentsv1alpha1.TrafficPolicyPeer) (peer, error) {
	if in.CIDR != "" {
		prefix, err := netip.ParsePrefix(in.CIDR)
		if err != nil {
			addr, addrErr := netip.ParseAddr(in.CIDR)
			if addrErr != nil {
				return peer{}, fmt.Errorf("invalid CIDR %q: %w", in.CIDR, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		return peer{kind: peerCIDR, prefix: prefix.Masked()}, nil
	}
	if in.FQDN != "" {
		return peer{kind: peerFQDN, fqdn: normalizeHostname(in.FQDN)}, nil
	}
	// Service and Workload references need a second address-set watcher. Keep
	// them explicit and non-matching in this CONNECT-address PoC rather than
	// accidentally treating them as an unconstrained peer.
	return peer{kind: peerUnsupported}, nil
}

func compilePort(in agentsv1alpha1.TrafficPolicyPort) (port, error) {
	protocol := strings.ToUpper(in.Protocol)
	if protocol != "" && protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" && protocol != "SCTP" {
		return port{}, fmt.Errorf("unsupported protocol %q", in.Protocol)
	}
	out := port{protocol: protocol}
	if in.Port != nil {
		out.start = *in.Port
		out.end = out.start
	}
	if in.EndPort != nil {
		if in.Port == nil || *in.EndPort < *in.Port {
			return port{}, fmt.Errorf("invalid port range")
		}
		out.end = *in.EndPort
	}
	return out, nil
}

func (r rule) matches(host string, destinationPort int32) bool {
	if len(r.ports) > 0 && !matchPorts(r.ports, destinationPort) {
		return false
	}
	if len(r.to) == 0 {
		return true
	}
	for _, candidate := range r.to {
		if candidate.matches(host) {
			return true
		}
	}
	return false
}

func matchPorts(ports []port, destinationPort int32) bool {
	for _, candidate := range ports {
		// CONNECT represents a TCP stream. A protocol-only TCP entry matches
		// every destination port, while UDP/ICMP/SCTP entries cannot match.
		if candidate.protocol != "" && candidate.protocol != "TCP" {
			continue
		}
		if candidate.start == 0 {
			return true
		}
		if destinationPort >= candidate.start && destinationPort <= candidate.end {
			return true
		}
	}
	return false
}

func (p peer) matches(host string) bool {
	switch p.kind {
	case peerCIDR:
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		return err == nil && p.prefix.Contains(addr)
	case peerFQDN:
		return matchHostname(p.fqdn, normalizeHostname(host))
	default:
		return false
	}
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func matchHostname(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return pattern == host
}
