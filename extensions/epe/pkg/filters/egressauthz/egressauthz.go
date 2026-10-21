// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package egressauthz authorizes resolved destinations and pins the selected
// upstream address so the proxy can connect to the address that was authorized.
package egressauthz

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	"github.com/openkruise/agentio/pkg/dns"
)

// Authorize checks the selected or resolved destination against one immutable
// config. It runs independently of the request rule chain and needs no body.
func Authorize(
	ctx context.Context,
	cfg Config,
	client *dns.Client,
	stream *filter.Stream,
) (*filter.UpstreamTarget, *filter.Reply, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("egressauthz config: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if stream == nil {
		return nil, nil, fmt.Errorf("request stream is required")
	}
	logger := log.FromContext(ctx).V(logging.DEBUG)
	evaluate := func(address netip.AddrPort) Decision {
		decision := cfg.Evaluate(address)
		if logger.Enabled() {
			logger.Info("egress destination evaluated",
				"address", address.String(), "action", string(decision.Action),
				"policy", decision.PolicyName, "ruleIndex", decision.RuleIndex)
		}
		record := filter.AuthorizationDecision{
			Action:      "deny",
			Destination: address.String(),
			Reason:      filter.AuthorizationReasonPolicyDenied,
		}
		if decision.PolicyName != "" {
			record.Policy, record.RuleIndex = decision.PolicyName, &decision.RuleIndex
		}
		if decision.Action == Allow {
			record.Action, record.Reason = "allow", ""
		}
		stream.Info.RecordAuthorization(record)
		return decision
	}
	// An explicit route is a fixed target, not a DNS candidate. Authorize its
	// actual IP and port and retain it; denying it must not choose another target.
	if stream.Upstream != nil {
		if err := (&filter.RouteMutation{Upstream: stream.Upstream}).Validate(); err != nil {
			return nil, nil, fmt.Errorf("egressauthz upstream: %w", err)
		}
		if evaluate(*stream.Upstream.Address).Action == Allow {
			return stream.Upstream, nil, nil
		}
		return denied()
	}
	addresses, err := resolveDNS(ctx, client, stream, cfg.Family)
	if err != nil {
		stream.Info.RecordAuthorization(
			filter.AuthorizationDecision{
				Action: "error",
				Reason: filter.AuthorizationReasonResolutionFailed,
			},
		)
		return nil, nil, fmt.Errorf("egressauthz: %w", err)
	}
	original := stream.Request.OriginalDestination
	if original.IsValid() &&
		slices.Contains(addresses, original.Addr().Unmap()) {
		address := netip.AddrPortFrom(original.Addr().Unmap(), uint16(stream.Request.Port))
		if evaluate(address).Action == Allow {
			return selectTarget(address), nil, nil
		}
		return denied()
	}
	// The same request snapshot governs DNS completion and every candidate.
	// Publishing a new Config cannot change this invocation's policy decisions.
	for _, ip := range addresses {
		address := netip.AddrPortFrom(ip, uint16(stream.Request.Port))
		decision := evaluate(address)
		if decision.Action != Allow {
			continue
		}
		return selectTarget(address), nil, nil
	}
	if len(addresses) != 1 {
		stream.Info.RecordAuthorization(
			filter.AuthorizationDecision{Action: "deny", Reason: filter.AuthorizationReasonPolicyDenied},
		)
	}
	return denied()
}

func selectTarget(address netip.AddrPort) *filter.UpstreamTarget {
	return &filter.UpstreamTarget{Address: &address}
}

func denied() (*filter.UpstreamTarget, *filter.Reply, error) {
	return nil, &filter.Reply{Status: 403, Details: "epe_egress_denied"}, nil
}
