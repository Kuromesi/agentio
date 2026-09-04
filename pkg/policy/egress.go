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
	"net/netip"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/validation"

	"istio.io/istio/pkg/util/sets"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
)

const unreachableCIDR = "192.0.0.8/32"

func CompileEgressPolicies(ctx krt.HandlerContext, config *configv1.AgentioConfig, resolve HostnameResolver) (*extensionsv1.EgressPolicies, error) {
	result := &extensionsv1.EgressPolicies{}
	if config == nil {
		return result, nil
	}
	for index, source := range config.GetEgressPolicies() {
		if source == nil {
			return nil, fmt.Errorf("egress policy %d is nil", index)
		}
		compiled := proto.Clone(source).(*extensionsv1.EgressPolicy)
		if err := validateEgressPolicy(index, compiled); err != nil {
			return nil, err
		}
		seen := sets.NewWithLength[string](len(compiled.GetMatchCidrs()))
		cidrs := make([]string, 0, len(compiled.GetMatchCidrs())+len(compiled.GetMatchHosts()))
		for _, cidr := range compiled.GetMatchCidrs() {
			prefix, _ := netip.ParsePrefix(cidr)
			normalized := prefix.Masked().String()
			if !seen.Contains(normalized) {
				seen.Insert(normalized)
				cidrs = append(cidrs, normalized)
			}
		}
		resolvedAny := false
		for _, hostname := range compiled.GetMatchHosts() {
			if resolve == nil {
				continue
			}
			for _, address := range resolve(ctx, strings.ToLower(strings.TrimSuffix(hostname, "."))) {
				bits := 32
				if address.Is6() {
					bits = 128
				}
				cidr := netip.PrefixFrom(address.Unmap(), bits).String()
				if !seen.Contains(cidr) {
					seen.Insert(cidr)
					cidrs = append(cidrs, cidr)
				}
				resolvedAny = true
			}
		}
		if len(compiled.GetMatchHosts()) > 0 && !resolvedAny && len(cidrs) == 0 {
			cidrs = append(cidrs, unreachableCIDR)
		}
		compiled.MatchCidrs = cidrs
		compiled.MatchHosts = nil
		result.EgressPolicies = append(result.EgressPolicies, compiled)
	}
	return result, nil
}

func validateEgressPolicy(index int, policy *extensionsv1.EgressPolicy) error {
	for _, cidr := range policy.GetMatchCidrs() {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("egress policy %d has invalid CIDR %q: %w", index, cidr, err)
		}
	}
	for _, port := range policy.GetMatchPorts() {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return fmt.Errorf("egress policy %d has invalid port %q", index, port)
		}
	}
	for _, host := range policy.GetMatchHosts() {
		normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if normalized == "" || len(validation.IsDNS1123Subdomain(normalized)) > 0 {
			return fmt.Errorf("egress policy %d has invalid hostname %q", index, host)
		}
	}
	if policy.GetPolicy() == extensionsv1.EgressPolicyAction_GATEWAY {
		gateway := policy.GetGateway()
		if gateway.GetService() == "" || gateway.GetPort() > 65535 {
			return fmt.Errorf("egress policy %d gateway requires service and port in range 0-65535", index)
		}
	}
	return nil
}
