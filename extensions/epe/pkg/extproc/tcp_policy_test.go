// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package extproc

import (
	"net/netip"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestSecurityProfileTCPFallthroughAfterHTTPRules(t *testing.T) {
	regs, err := filter.Build(bypass.Definition(), block.Definition(), headermutation.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		action    agents.SecurityRuleActions
		tcpAction string
		global    bool
		status    int
	}{
		{name: "empty HTTP rules", tcpAction: "deny", status: 403},
		{name: "mutation falls through", action: agents.SecurityRuleActions{HeaderManipulation: &agents.HeaderManipulationAction{Set: []agents.HeaderValue{{Name: "x-token", Value: "injected"}}}}, tcpAction: "deny", status: 403},
		{name: "bypass skips TCP deny", action: agents.SecurityRuleActions{Bypass: true}, tcpAction: "deny"},
		{name: "block wins over TCP allow", action: agents.SecurityRuleActions{Block: &agents.BlockAction{StatusCode: 451}}, tcpAction: "allow", status: 451},
		{name: "bypass preserves platform deny", action: agents.SecurityRuleActions{Bypass: true}, tcpAction: "deny", global: true, status: 403},
		{name: "TCP allow pins address", tcpAction: "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := profilestore.MakeFakeStore(regs...)
			spec := agents.SecurityProfileSpec{
				TCPRules: []agents.TCPRule{
					{
						Name:   "target",
						Action: tc.tcpAction,
						Match:  []agents.TCPMatch{{CIDRs: []string{"10.0.0.0/8"}, Ports: []int32{443}}},
					},
				},
			}
			if tc.action.Bypass || tc.action.Block != nil || tc.action.HeaderManipulation != nil {
				spec.Rules = []agents.SecurityRule{
					{Name: "http", Match: []agents.RuleMatch{{Domains: []string{"*"}}}, Actions: tc.action},
				}
			}
			store.ProfileSet(
				&agents.SecurityProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile", Namespace: "ns"}, Spec: spec},
			)
			global := egressauthz.Config{}
			if tc.global {
				global.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			}
			srv := NewServer(
				ServerDeps{
					Registrations: regs,
					Resolve:       securityprofile.NewResolver(store, regs, nil),
					AuthorizeRequest: egressauthz.NewAggregate(
						dns.NewClient(nil, 0),
						egressauthz.NewStaticAuthorizer(global),
						securityprofile.NewAuthorizer(),
					).Authorize,
				},
			)
			state := newStreamState()
			headers := makeRequestHeaders("10.1.2.3:443", "/", "GET")
			responses, err := srv.HandleRequestHeaders(
				t.Context(),
				headers,
				makeAttrsWithLabels("ns", "pod", ""),
				state,
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != 0 {
				if got := int(responses[0].GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
					t.Fatalf("status=%d, want %d: %v", got, tc.status, responses)
				}
			} else if got := responseUpstream(responses[0]).GetFields()[upstreamAddressField].GetStringValue(); got != "10.1.2.3:443" {
				t.Fatalf("target not pinned: %s", got)
			}
		})
	}
}
