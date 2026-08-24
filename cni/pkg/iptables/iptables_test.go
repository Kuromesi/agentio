// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package iptables

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"istio.io/istio/cni/pkg/config"
	"istio.io/istio/cni/pkg/scopes"
	testutil "istio.io/istio/pilot/test/util"
	"istio.io/istio/pkg/test/util/assert"
	dep "istio.io/istio/tools/istio-iptables/pkg/dependencies"
)

func TestIptablesPodOverrides(t *testing.T) {
	cases := GetCommonInPodTestCases()

	for _, tt := range cases {
		for _, ipv6 := range []bool{false, true} {
			t.Run(tt.name+"_"+ipstr(ipv6), func(t *testing.T) {
				cfg := constructTestConfig()
				cfg.EnableIPv6 = ipv6
				tt.config(cfg)
				ext := &dep.DependenciesStub{}
				iptConfigurator, _, _ := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
				err := iptConfigurator.CreateInpodRules(scopes.CNIAgent, tt.podOverrides)
				if err != nil {
					t.Fatal(err)
				}

				compareToGolden(t, ipv6, tt.name, ext.ExecutedAll)
			})
		}
	}
}

func TestIptablesPodLevelReroutesAndExclusions(t *testing.T) {
	cfg := constructTestConfig()
	ext := &dep.DependenciesStub{}
	iptConfigurator, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	if err != nil {
		t.Fatal(err)
	}
	if err := iptConfigurator.CreateInpodRules(scopes.CNIAgent, config.PodLevelOverrides{
		BridgePortPrefixes:      []string{"msb-tap"},
		RerouteSourceIPRanges:   []netip.Prefix{netip.MustParsePrefix("169.254.0.21/32")},
		ExcludeOutboundPorts:    []uint16{9862},
		ExcludeOutboundIPRanges: []netip.Prefix{netip.MustParsePrefix("169.254.0.21/32")},
	}); err != nil {
		t.Fatal(err)
	}

	got := strings.Join(ext.ExecutedAll, "\n")
	redirect := "-A ISTIO_PRERT -p tcp -m physdev --physdev-in msb-tap+ -j REDIRECT --to-ports 15001"
	returnRule := "-A ISTIO_PRERT -p tcp -m physdev --physdev-in msb-tap+ -j RETURN"
	sourceRedirect := "-A ISTIO_PRERT -s 169.254.0.21/32 -p tcp ! --dport 15001 -j REDIRECT --to-ports 15001"
	sourceReturn := "-A ISTIO_PRERT -s 169.254.0.21/32 -p tcp -j RETURN"
	inbound := "-A ISTIO_PRERT ! -d 127.0.0.1/32 -p tcp ! --dport 15008"
	excludePort := "-A ISTIO_OUTPUT -p tcp --dport 9862 -j ACCEPT"
	excludeRange := "-A ISTIO_OUTPUT -p tcp -d 169.254.0.21/32 -j ACCEPT"
	outbound := "-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15001"
	for _, want := range []string{redirect, returnRule, sourceRedirect, sourceReturn, excludePort, excludeRange} {
		if !strings.Contains(got, want) {
			t.Fatalf("iptables rules do not contain %q:\n%s", want, got)
		}
	}
	if strings.Index(got, redirect) > strings.Index(got, inbound) {
		t.Fatalf("bridge redirect must precede ordinary inbound capture:\n%s", got)
	}
	if strings.Index(got, sourceRedirect) > strings.Index(got, inbound) || strings.Index(got, sourceReturn) > strings.Index(got, inbound) {
		t.Fatalf("source IP redirect must precede ordinary inbound capture:\n%s", got)
	}
	for _, exclude := range []string{excludePort, excludeRange} {
		if strings.Index(got, exclude) > strings.Index(got, outbound) {
			t.Fatalf("outbound exclusion must precede ordinary outbound capture:\n%s", got)
		}
	}
}

func TestIPv6NotAvailable(t *testing.T) {
	setup(t)
	cfg := constructTestConfig()
	ext := &dep.DependenciesStub{
		ForceIPv6DetectionFail: true,
	}

	// Istio shouldn't fail if we're working with IPv4 interfaces only, and ip6tables is unavailable.
	cfg.EnableIPv6 = false
	_, _, err := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.NoError(t, err)

	cfg.EnableIPv6 = true
	_, _, err = NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
	assert.Error(t, err)
}

func TestIptablesHostRules(t *testing.T) {
	cases := GetCommonHostTestCases()

	for _, tt := range cases {
		for _, ipv6 := range []bool{false, true} {
			t.Run(tt.name+"_"+ipstr(ipv6), func(t *testing.T) {
				cfg := constructTestConfig()
				cfg.EnableIPv6 = ipv6
				cfg.HostProbeSNATAddress = netip.MustParseAddr("169.254.7.127")
				cfg.HostProbeV6SNATAddress = netip.MustParseAddr("fd16:9254:7127:1337:ffff:ffff:ffff:ffff")
				tt.config(cfg)
				ext := &dep.DependenciesStub{}
				iptConfigurator, _, _ := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
				err := iptConfigurator.CreateHostRulesForHealthChecks()
				if err != nil {
					t.Fatal(err)
				}

				compareToGolden(t, ipv6, tt.name, ext.ExecutedAll)
			})
		}
	}
}

func TestInvokedTwiceIsIdempotent(t *testing.T) {
	tests := GetCommonInPodTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := constructTestConfig()
			tt.config(cfg)
			ext := &dep.DependenciesStub{}
			iptConfigurator, _, _ := NewIptablesConfigurator(cfg, cfg, ext, ext, EmptyNlDeps())
			err := iptConfigurator.CreateInpodRules(scopes.CNIAgent, tt.podOverrides)
			if err != nil {
				t.Fatal(err)
			}
			compareToGolden(t, false, tt.name, ext.ExecutedAll)

			*ext = dep.DependenciesStub{}
			// run another time to make sure we are idempotent
			err = iptConfigurator.CreateInpodRules(scopes.CNIAgent, tt.podOverrides)
			if err != nil {
				t.Fatal(err)
			}
			compareToGolden(t, false, tt.name, ext.ExecutedAll)
		})
	}
}

func ipstr(ipv6 bool) string {
	if ipv6 {
		return "ipv6"
	}
	return "ipv4"
}

func compareToGolden(t *testing.T, ipv6 bool, name string, actual []string) {
	t.Helper()
	gotBytes := []byte(strings.Join(actual, "\n"))
	goldenFile := filepath.Join("testdata", name+".golden")
	if ipv6 {
		goldenFile = filepath.Join("testdata", name+"_ipv6.golden")
	}
	testutil.CompareContent(t, gotBytes, goldenFile)
}

func constructTestConfig() *config.AmbientConfig {
	probeSNATipv4 := netip.MustParseAddr("169.254.7.127")
	probeSNATipv6 := netip.MustParseAddr("e9ac:1e77:90ca:399f:4d6d:ece2:2f9b:3164")
	return &config.AmbientConfig{
		HostProbeSNATAddress:   probeSNATipv4,
		HostProbeV6SNATAddress: probeSNATipv6,
	}
}
