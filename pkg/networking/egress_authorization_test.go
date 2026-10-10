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

package networking

import (
	"slices"
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestEgressAuthorizationPinsDFPTarget(t *testing.T) {
	in := Inputs{
		Gateway:          testGateway(&configv1.EgressGateway{}),
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
	}
	if _, err := Build(in); err != nil {
		t.Fatal(err)
	}
	in.GlobalExtProc = &configv1.ExtProcProvider{
		Service:          "epe",
		Port:             9002,
		FailureModeAllow: true,
		Request:          &configv1.ProcessingModeOptions{HeaderMode: configv1.HeaderSendMode_SKIP}}
	resources, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listener.Listener { return &listener.Listener{} })
	for _, name := range []string{MainInternal, MainForward} {
		h := findHCM(t, listeners[name])
		names := []string{}
		for _, f := range h.HttpFilters {
			names = append(names, f.Name)
			if f.Name == "agentio.egress_target_guard" {
				t.Error("unexpected rejection when EPE returns no target")
			}
			if f.Name == "agentio.egress_target" {
				cfg := &state.Config{}
				if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
					t.Fatal(err)
				}
				for _, value := range cfg.OnRequestHeaders {
					if !value.SkipIfEmpty || !value.GetFormatString().GetOmitEmptyValues() {
						t.Error("missing target must leave DFP filter state unchanged")
					}
				}
			}
			if f.Name == "envoy.filters.http.ext_proc" {
				cfg := &extproc.ExternalProcessor{}
				if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
					t.Fatal(err)
				}
				if !cfg.GetFailureModeAllow() || cfg.GetProcessingMode().GetRequestHeaderMode() != extproc.ProcessingMode_SKIP {
					t.Fatal("provider failure and header modes must be preserved")
				}
				if !slices.Contains(cfg.GetMetadataOptions().GetReceivingNamespaces().GetUntyped(), "agentio.route") {
					t.Fatal("route metadata discarded")
				}
			}
		}
		if slices.Index(names, "agentio.egress_target") <= slices.Index(names, "envoy.filters.http.ext_proc") ||
			slices.Index(
				names,
				"agentio.egress_target",
			) >= slices.Index(
				names,
				"envoy.filters.http.dynamic_forward_proxy",
			) {
			t.Fatalf("filter order %v", names)
		}
	}
}
