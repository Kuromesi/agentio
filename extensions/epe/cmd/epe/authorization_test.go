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

package main

import (
	"context"
	"flag"
	"testing"
	"testing/synctest"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestXDSEgressAuthorizationFlag(t *testing.T) {
	f := flag.Lookup("enable-xds-egressauthz")
	if f == nil || f.DefValue != "false" {
		t.Fatal("xDS authorization must be opt-in")
	}
	if flag.Lookup("enable-egressauthz") != nil {
		t.Fatal("legacy opt-in authorization flag is still registered")
	}
}

func TestValidateGlobalDeniedCIDRs(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{"127.0.0.0/8", true}, {"::1/128", true}, {"192.0.2.1/32", true},
		{"192.0.2.9/24", true}, {"0.0.0.0/0", true}, {"::/0", true},
		{"localhost", false}, {"127.0.0.1", false}, {"127.0.0.1/33", false},
		{"::ffff:127.0.0.1/128", false}, {"fe80::1%eth0/128", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := &configv1.EPEConfig{
				EgressAuthorization: &configv1.EgressAuthorization{DeniedCidrs: []string{tc.raw}},
			}
			if err := validateEPEConfig(cfg); (err == nil) != tc.valid {
				t.Fatalf("validation=%v, valid=%t", err, tc.valid)
			}
		})
	}
}

func TestStaticAuthorizationConfigLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cm := func(name, content string) *corev1.ConfigMap {
			return &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "system"},
				Data:       map[string]string{"config": content},
			}
		}
		defaults, err := wiring.DefaultEPEConfig()
		if err != nil {
			t.Fatal(err)
		}
		sources := krt.NewMutableCollection(nil, []*corev1.ConfigMap{}, krt.WithStop(ctx.Done()))
		configs := config.NewCollection(sources.AsCollection(), config.Options[*configv1.EPEConfig]{
			Namespace: "system",
			Names:     []string{"base", "primary"},
			Defaults:  defaults,
			Apply:     extensionprovider.ApplyConfig,
			Validate:  validateEPEConfig,
		}, krt.WithStop(ctx.Done()))
		// No resource store, xDS connection, workload binding, or source identity.
		authorize, reg := newRequestAuthorizer(configs.AsCollection(), nil, dns.NewClient(nil, 0))
		if !reg.WaitUntilSynced(ctx.Done()) {
			t.Fatal("authorization configuration did not sync")
		}
		check := func(host string, denied bool) {
			t.Helper()
			synctest.Wait()
			target, reply, err := authorize(ctx, &filter.Stream{Request: httpreq.HTTPRequest{Host: host, Port: 15000}})
			if err != nil {
				t.Fatal(err)
			}
			if denied {
				if reply == nil || reply.Status != 403 || target != nil {
					t.Fatalf("%s: target=%v reply=%v", host, target, reply)
				}
			} else if reply != nil || target == nil {
				t.Fatalf("%s: target=%v reply=%v", host, target, reply)
			}
		}
		// Built-in restrictions apply without any ConfigMap, including mapped IPv4.
		for _, host := range []string{"127.0.0.1", "127.255.255.254", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "::ffff:0.0.0.0"} {
			check(host, true)
		}
		check("192.0.2.1", false)
		sources.UpdateObject(cm("base", "egressAuthorization: {deniedCIDRs: [invalid]}"))
		check("127.0.0.1", true) // Invalid initial user configuration retains defaults.
		check("0.0.0.0", true)
		sources.UpdateObject(cm("base", "egressAuthorization: {deniedCIDRs: [127.0.0.0/8]}"))
		check("127.0.0.1", true)
		check("192.0.2.1", false)
		sources.UpdateObject(cm("primary", "egressAuthorization: null"))
		check("127.0.0.1", true) // Null inherits the lower layer.
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: ['::1/128']}"))
		check("::1", true)
		check("127.0.0.1", false) // Supplied block replaces the lower layer.
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: [invalid]}"))
		check("::1", true) // Invalid update keeps the last good snapshot.
		check("127.0.0.1", false)
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: []}"))
		check("::1", false)
		sources.DeleteObject("system/primary")
		check("127.0.0.1", true)
		sources.DeleteObject("system/base")
		check("127.0.0.1", true) // Deleting overrides restores built-in restrictions.
		check("0.0.0.0", true)
	})
}
