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
	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
)

type hostnameResolver func(krt.HandlerContext, string) []string

// unreachableCIDR is the IANA IPv4 Dummy Address (RFC 7600). It prevents a
// host-only policy from becoming a wildcard when every hostname fails to resolve.
const unreachableCIDR = "192.0.0.8/32"

type ResolvedEgressPolicies struct {
	Policies *extensions.EgressPolicies
}

func (r ResolvedEgressPolicies) ResourceName() string {
	return "resolved-egress-policies"
}

func (r ResolvedEgressPolicies) Equals(other ResolvedEgressPolicies) bool {
	return proto.Equal(r.Policies, other.Policies)
}

func (r ResolvedEgressPolicies) GetEgressPolicies() []*extensions.EgressPolicy {
	if r.Policies == nil {
		return nil
	}
	return r.Policies.GetEgressPolicies()
}

func newResolvedEgressPolicies(
	config krt.Singleton[model.AgentioConfig],
	resolve hostnameResolver,
	opts krt.OptionsBuilder,
) krt.Singleton[ResolvedEgressPolicies] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *ResolvedEgressPolicies {
		var policies []*extensions.EgressPolicy
		if cfg := krt.FetchOne(ctx, config.AsCollection()); cfg != nil {
			policies = cfg.GetEgressPolicies()
		}
		return &ResolvedEgressPolicies{
			Policies: &extensions.EgressPolicies{
				EgressPolicies: resolveEgressPolicies(ctx, policies, resolve),
			},
		}
	}, opts.WithName("ResolvedEgressPolicies")...)
}

func resolveEgressPolicies(
	ctx krt.HandlerContext,
	policies []*extensions.EgressPolicy,
	resolve hostnameResolver,
) []*extensions.EgressPolicy {
	resolvedPolicies := make([]*extensions.EgressPolicy, 0, len(policies))
	for _, policy := range policies {
		if policy == nil {
			resolvedPolicies = append(resolvedPolicies, nil)
			continue
		}

		compiled := proto.Clone(policy).(*extensions.EgressPolicy)
		hasConfiguredCIDRs := len(compiled.GetMatchCidrs()) > 0
		resolvedHost := false
		for _, hostname := range compiled.GetMatchHosts() {
			addresses := resolve(ctx, hostname)
			if len(addresses) == 0 {
				log.Warnf("failed to resolve match_hosts entry %q, policy may not match intended traffic", hostname)
				continue
			}
			for _, address := range addresses {
				compiled.MatchCidrs = append(compiled.MatchCidrs, address+"/32")
			}
			resolvedHost = true
		}
		if len(compiled.GetMatchHosts()) > 0 && !resolvedHost && !hasConfiguredCIDRs {
			compiled.MatchCidrs = append(compiled.MatchCidrs, unreachableCIDR)
		}
		compiled.MatchHosts = nil
		resolvedPolicies = append(resolvedPolicies, compiled)
	}
	return resolvedPolicies
}
