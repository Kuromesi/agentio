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

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	celenv "github.com/google/cel-go/common/env"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestDefaultAccessLogFields(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := t.TempDir()
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 0.1.0\n")
	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, chart, template string
		values                map[string]any
	}{
		{name: "standalone", chart: source, template: "agentio/templates/meshconfig.yaml"},
		{name: "sandbox-manager", chart: target, template: "sandbox-manager/templates/agentio/meshconfig.yaml", values: map[string]any{"agentio": map[string]any{"enabled": true}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chart, err := loader.Load(filepath.Clean(tt.chart))
			if err != nil {
				t.Fatal(err)
			}
			values, err := chartutil.ToRenderValues(chart, tt.values, chartutil.ReleaseOptions{Name: "agentio", Namespace: "agentio-system", IsInstall: true}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := engine.Render(chart, values)
			if err != nil {
				t.Fatal(err)
			}
			var config corev1.ConfigMap
			if err := yaml.Unmarshal([]byte(rendered[tt.template]), &config); err != nil {
				t.Fatal(err)
			}
			var mesh struct {
				ExtensionProviders []struct {
					Name               string
					EnvoyFileAccessLog struct {
						OmitEmptyValues bool
						LogFormat       struct{ Labels map[string]string }
					}
				}
			}
			if err := yaml.Unmarshal([]byte(config.Data["mesh"]), &mesh); err != nil {
				t.Fatal(err)
			}
			for _, provider := range mesh.ExtensionProviders {
				if provider.Name != "envoy" {
					continue
				}
				if !provider.EnvoyFileAccessLog.OmitEmptyValues {
					t.Fatal("empty fields must be omitted")
				}
				labels := provider.EnvoyFileAccessLog.LogFormat.Labels
				for key, want := range map[string]string{
					"scheme": "%REQ(:SCHEME)%", "protocol": "%PROTOCOL%", "authority_for": "%REQ(:AUTHORITY)%",
					"original_destination": "%DOWNSTREAM_LOCAL_ADDRESS%", "upstream_address": "%UPSTREAM_REMOTE_ADDRESS%",
					"upstream_host": "%UPSTREAM_HOST%", "denial_reason": "%FILTER_STATE(io.kruise.egress_denial_reason:PLAIN)%",
					"response_code_details": "%RESPONSE_CODE_DETAILS%", "connection_termination_details": "%CONNECTION_TERMINATION_DETAILS%",
					"log_type": "%ACCESS_LOG_TYPE%",
				} {
					if got := labels[key]; got != want {
						t.Errorf("%s = %q, want %q", key, got, want)
					}
				}
				for _, key := range []string{"upstream_cluster", "filter_chain"} {
					if _, found := labels[key]; found {
						t.Errorf("default logs must not expose internal %s names", key)
					}
				}
				testAccessLogSNI(t, labels["requested_server_name"])
				return
			}
			t.Fatal("rendered MeshConfig is missing the envoy access-log provider")
		})
	}
}

func testAccessLogSNI(t *testing.T, format string) {
	t.Helper()
	if !strings.HasPrefix(format, "%CEL(") || !strings.HasSuffix(format, ")%") {
		t.Fatalf("SNI format = %q, want CEL", format)
	}
	// Envoy's default CEL builder disables string conversion. Its filter-state
	// map is dynamically typed and exposes unstructured objects as bytes.
	environment, err := cel.NewCustomEnv(
		cel.StdLib(cel.StdLibSubset(celenv.NewLibrarySubset().AddExcludedFunctions(celenv.NewFunction("string")))),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("connection", cel.MapType(cel.StringType, cel.StringType)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := environment.Compile(strings.TrimSuffix(strings.TrimPrefix(format, "%CEL("), ")%"))
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	program, err := environment.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		state     map[string][]byte
		socketSNI string
		want      string
	}{
		{name: "plaintext HTTP", state: map[string][]byte{}, want: ""},
		{name: "TLS passthrough", state: map[string][]byte{}, socketSNI: "passthrough.example.com", want: "passthrough.example.com"},
		{name: "TLS without SNI", state: map[string][]byte{}, want: ""},
		{name: "decrypted HTTPS", state: map[string][]byte{"io.kruise.outer_sni": []byte("api.example.com")}, want: "api.example.com"},
		{name: "outer SNI wins over inner connection", state: map[string][]byte{"io.kruise.outer_sni": []byte("proxy.example.com")}, socketSNI: "inner.example.com", want: "proxy.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Envoy exposes an unstructured filter-state string as CEL bytes. No
			// request attributes exist for TCP logs, so do not supply them here.
			got, _, err := program.Eval(map[string]any{
				"filter_state": tt.state,
				"connection":   map[string]string{"requested_server_name": tt.socketSNI},
			})
			if err != nil {
				t.Fatal(err)
			}
			// Envoy's non-typed CEL formatter prints both bytes and strings
			// directly. TYPED_CEL has different byte serialization semantics.
			var printed string
			switch value := got.Value().(type) {
			case string:
				printed = value
			case []byte:
				printed = string(value)
			default:
				t.Fatalf("SNI result has unexpected type %T", value)
			}
			if printed != tt.want {
				t.Errorf("SNI = %q, want %q", printed, tt.want)
			}
		})
	}
}
