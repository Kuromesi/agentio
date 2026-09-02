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
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
)

func TestApplyAgentioConfig_BasicOverride(t *testing.T) {
	t.Run("ext_proc set and default ignored labels preserved", func(t *testing.T) {
		defaults := model.DefaultAgentioConfig()
		yml := `
sandboxExtProc:
  service: "ext-proc.example.com"
  port: 9090
`
		got, err := applyAgentioConfig(yml, defaults)
		if err != nil {
			t.Fatalf("applyAgentioConfig failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "ext-proc.example.com" {
			t.Errorf("service: expected ext-proc.example.com, got %s", extProc.GetService())
		}
		if extProc.GetPort() != 9090 {
			t.Errorf("port: expected 9090, got %d", extProc.GetPort())
		}

		// Default ignored labels should be preserved since override YAML does not include them.
		wantLabels := defaults.GetSandboxIgnoredLabels()
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
		}
	})
}

func TestApplyAgentioConfig_FullSubMessageReplacement(t *testing.T) {
	t.Run("override replaces entire sub-message, unset fields reset to zero", func(t *testing.T) {
		base := &model.AgentioConfig{
			AgentioConfig: &extensions.AgentioConfig{
				SandboxExtProc: &extensions.ExtProcProvider{
					Service: "old.example.com",
					Port:    8080,
				},
			},
		}
		// Override only sets service; port is absent so it should become 0.
		yml := `
sandboxExtProc:
  service: "new.example.com"
`
		got, err := applyAgentioConfig(yml, base)
		if err != nil {
			t.Fatalf("applyAgentioConfig failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "new.example.com" {
			t.Errorf("service: expected new.example.com, got %s", extProc.GetService())
		}
		// Key semantic difference from old deep-merge: port is NOT preserved from base.
		if extProc.GetPort() != 0 {
			t.Errorf("port: expected 0 (reset), got %d", extProc.GetPort())
		}
	})
}

func TestApplyAgentioConfig_RepeatedFieldReplacement(t *testing.T) {
	t.Run("override fully replaces repeated field", func(t *testing.T) {
		base := &model.AgentioConfig{
			AgentioConfig: &extensions.AgentioConfig{
				SandboxIgnoredLabels: []string{"a", "b"},
			},
		}
		yml := `
sandboxIgnoredLabels:
  - "c"
`
		got, err := applyAgentioConfig(yml, base)
		if err != nil {
			t.Fatalf("applyAgentioConfig failed: %v", err)
		}

		want := []string{"c"}
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, want) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", want, gotLabels)
		}
	})
}

func TestApplyAgentioConfig_MultiLayerMerge(t *testing.T) {
	t.Run("default -> base -> primary three-layer merge", func(t *testing.T) {
		defaults := model.DefaultAgentioConfig()

		// Base layer: sets ext_proc, does not touch ignored labels.
		baseYml := `
sandboxExtProc:
  service: "base.example.com"
  port: 8080
`
		afterBase, err := applyAgentioConfig(baseYml, defaults)
		if err != nil {
			t.Fatalf("applyAgentioConfig (base) failed: %v", err)
		}

		// Primary layer: overrides ext_proc service only (port resets to 0).
		primaryYml := `
sandboxExtProc:
  service: "primary.example.com"
`
		got, err := applyAgentioConfig(primaryYml, afterBase)
		if err != nil {
			t.Fatalf("applyAgentioConfig (primary) failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "primary.example.com" {
			t.Errorf("service: expected primary.example.com, got %s", extProc.GetService())
		}
		// Port was set by base but primary's sandboxExtProc replaces the whole sub-message.
		if extProc.GetPort() != 0 {
			t.Errorf("port: expected 0 (reset by primary override), got %d", extProc.GetPort())
		}

		// Ignored labels were never touched by either override, so defaults survive.
		wantLabels := defaults.GetSandboxIgnoredLabels()
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected defaults %v, got %v", wantLabels, gotLabels)
		}
	})
}

func TestApplyAgentioConfig_EmptyOverride(t *testing.T) {
	cases := []struct {
		name string
		yml  string
	}{
		{"empty string", ""},
		{"empty object", "{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaults := model.DefaultAgentioConfig()
			got, err := applyAgentioConfig(tc.yml, defaults)
			if err != nil {
				t.Fatalf("applyAgentioConfig failed: %v", err)
			}

			// Defaults should be fully preserved.
			wantLabels := defaults.GetSandboxIgnoredLabels()
			gotLabels := got.GetSandboxIgnoredLabels()
			if !reflect.DeepEqual(gotLabels, wantLabels) {
				t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
			}

			// ext_proc should remain nil (not set in defaults or override).
			if got.GetSandboxExtProc() != nil {
				t.Errorf("expected nil sandboxExtProc, got %+v", got.GetSandboxExtProc())
			}
		})
	}
}

func TestApplyAgentioConfig_NilDefaultConfig(t *testing.T) {
	t.Run("nil default produces valid output from override", func(t *testing.T) {
		yml := `
sandboxExtProc:
  service: "from-nil.example.com"
  port: 7070
sandboxIgnoredLabels:
  - "x"
  - "y"
`
		got, err := applyAgentioConfig(yml, nil)
		if err != nil {
			t.Fatalf("applyAgentioConfig failed: %v", err)
		}
		if got == nil || got.AgentioConfig == nil {
			t.Fatal("expected non-nil result")
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "from-nil.example.com" {
			t.Errorf("service: expected from-nil.example.com, got %s", extProc.GetService())
		}
		if extProc.GetPort() != 7070 {
			t.Errorf("port: expected 7070, got %d", extProc.GetPort())
		}

		wantLabels := []string{"x", "y"}
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
		}
	})

	t.Run("nil default with empty yaml produces empty config", func(t *testing.T) {
		got, err := applyAgentioConfig("", nil)
		if err != nil {
			t.Fatalf("applyAgentioConfig failed: %v", err)
		}
		if got == nil || got.AgentioConfig == nil {
			t.Fatal("expected non-nil result with valid AgentioConfig")
		}
		if got.GetSandboxExtProc() != nil {
			t.Errorf("expected nil sandboxExtProc, got %+v", got.GetSandboxExtProc())
		}
		if len(got.GetSandboxIgnoredLabels()) != 0 {
			t.Errorf("expected empty sandboxIgnoredLabels, got %v", got.GetSandboxIgnoredLabels())
		}
	})
}

func TestApplyAgentioConfig_ServiceEntries(t *testing.T) {
	yml := `
egressGateways:
- name: egress-gw
  namespace: istio-system
  serviceEntries:
  - hosts:
    - API.Example.COM.
    endpoints:
    - address: " 10.10.20.30 "
    - address: 10.10.20.31
`
	got, err := applyAgentioConfig(yml, nil)
	if err != nil {
		t.Fatalf("applyAgentioConfig failed: %v", err)
	}

	entries := got.GetEgressGateways()[0].GetServiceEntries()
	if got, want := entries[0].GetHosts(), []string{"api.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
	var addresses []string
	for _, endpoint := range entries[0].GetEndpoints() {
		addresses = append(addresses, endpoint.GetAddress())
	}
	if want := []string{"10.10.20.30", "10.10.20.31"}; !reflect.DeepEqual(addresses, want) {
		t.Fatalf("endpoint addresses = %v, want %v", addresses, want)
	}
}

func TestApplyAgentioConfig_InvalidServiceEntries(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr string
	}{
		{
			name: "missing hosts",
			entry: `
    endpoints:
    - address: 10.10.20.30`,
			wantErr: ".hosts must contain at least one host",
		},
		{
			name: "wildcard host",
			entry: `
    hosts: ["*.example.com"]
    endpoints:
    - address: 10.10.20.30`,
			wantErr: ".hosts[0] is not a valid FQDN",
		},
		{
			name: "missing endpoints",
			entry: `
    hosts: ["api.example.com"]`,
			wantErr: ".endpoints must contain at least one endpoint",
		},
		{
			name: "non IPv4 endpoint",
			entry: `
    hosts: ["api.example.com"]
    endpoints:
    - address: 2001:db8::1`,
			wantErr: ".endpoints[0].address must be an IPv4 address",
		},
		{
			name: "duplicate endpoint",
			entry: `
    hosts: ["api.example.com"]
    endpoints:
    - address: 10.10.20.30
    - address: " 10.10.20.30 "`,
			wantErr: ".endpoints[1].address duplicates endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yml := `
egressGateways:
- name: egress-gw
  namespace: istio-system
  serviceEntries:
  -` + tt.entry + "\n"
			_, err := applyAgentioConfig(yml, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
