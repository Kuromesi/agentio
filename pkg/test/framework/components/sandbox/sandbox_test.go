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

package sandbox

import (
	"reflect"
	"testing"
)

func TestHelmValuesAddsExternalImagesWithoutMutatingConfig(t *testing.T) {
	original := map[string]string{"global.enableFirewallRules": "false"}
	cfg := Config{
		Values: original,
		ProxyImage: &ImageConfig{
			Hub:  "registry.example.com/dev",
			Name: "proxyv2",
			Tag:  "proxy-test",
		},
		ZtunnelImage: &ImageConfig{
			Hub:  "registry.example.com/dev",
			Name: "sandbox-tunnel",
			Tag:  "tunnel-test",
		},
	}

	got, err := cfg.helmValues()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"global.enableFirewallRules": "false",
		"proxy.image.hub":            "registry.example.com/dev",
		"proxy.image.name":           "proxyv2",
		"proxy.image.tag":            "proxy-test",
		"egressGateway.image.hub":    "registry.example.com/dev",
		"egressGateway.image.name":   "proxyv2",
		"egressGateway.image.tag":    "proxy-test",
		"ztunnel.image.hub":          "registry.example.com/dev",
		"ztunnel.image.name":         "sandbox-tunnel",
		"ztunnel.image.tag":          "tunnel-test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("helm values mismatch: got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(original, map[string]string{"global.enableFirewallRules": "false"}) {
		t.Fatalf("Config.Values was mutated: %v", original)
	}
}

func TestHelmValuesRejectsIncompleteExternalImage(t *testing.T) {
	cfg := Config{ProxyImage: &ImageConfig{Hub: "registry.example.com/dev", Name: "proxyv2"}}

	if _, err := cfg.helmValues(); err == nil {
		t.Fatal("expected incomplete proxy image to be rejected")
	}
}

func TestControlPlanePodSelector(t *testing.T) {
	if controlPlanePodSelector != "app=agentiod" {
		t.Fatalf("unexpected control-plane selector %q", controlPlanePodSelector)
	}
}
