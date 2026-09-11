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

package telemetry

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
)

func TestDefaultProvidersMatchAgentioChart(t *testing.T) {
	defaults := defaultTelemetryProviders(nil)
	if !slices.Equal(defaults.DefaultMetrics, []string{"prometheus"}) {
		t.Fatalf("default metrics = %v", defaults.DefaultMetrics)
	}
	if !slices.Equal(defaults.DefaultAccessLogging, []string{"envoy"}) {
		t.Fatalf("default access logging = %v", defaults.DefaultAccessLogging)
	}
	if len(defaults.DefaultTracing) != 0 {
		t.Fatalf("default tracing = %v, want none", defaults.DefaultTracing)
	}
	prometheus := defaults.Provider("PROMETHEUS")
	if prometheus == nil || !prometheus.Prometheus {
		t.Fatalf("prometheus provider = %+v", prometheus)
	}
	envoy := defaults.Provider("envoy")
	if envoy == nil || envoy.HTTPAccessLog == nil || envoy.TCPAccessLog == nil {
		t.Fatalf("envoy provider = %+v", envoy)
	}
	for protocol, accessLog := range map[string]*accesslogv3.AccessLog{"http": envoy.HTTPAccessLog, "tcp": envoy.TCPAccessLog} {
		fileLog := &fileaccesslogv3.FileAccessLog{}
		if err := accessLog.GetTypedConfig().UnmarshalTo(fileLog); err != nil {
			t.Fatalf("decode %s file access log: %v", protocol, err)
		}
		if fileLog.GetPath() != "/dev/stdout" || !fileLog.GetLogFormat().GetOmitEmptyValues() {
			t.Fatalf("%s file access log path/omit = %q/%v", protocol, fileLog.GetPath(), fileLog.GetLogFormat().GetOmitEmptyValues())
		}
		fields := fileLog.GetLogFormat().GetJsonFormat().GetFields()
		want := map[string]string{
			"scheme": "%REQ(:SCHEME)%", "original_destination": "%DOWNSTREAM_LOCAL_ADDRESS%",
			"upstream_host": "%UPSTREAM_HOST%", "upstream_cluster": "%UPSTREAM_CLUSTER%",
			"response_code_details": "%RESPONSE_CODE_DETAILS%", "connection_termination_details": "%CONNECTION_TERMINATION_DETAILS%",
			"filter_chain": "%FILTER_CHAIN_NAME%", "log_type": "%ACCESS_LOG_TYPE%",
			"authority_for": "%REQ(:AUTHORITY)%", "bytes_received": "%BYTES_RECEIVED%", "bytes_sent": "%BYTES_SENT%",
			"downstream_address": "%DOWNSTREAM_REMOTE_ADDRESS%", "duration": "%DURATION%", "method": "%REQ(:METHOD)%",
			"path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%", "protocol": "%PROTOCOL%", "request_id": "%REQ(X-REQUEST-ID)%",
			"requested_server_name": "%CEL('io.kruise.outer_sni' in filter_state ? string(filter_state['io.kruise.outer_sni']) : connection.requested_server_name)%", "response_code": "%RESPONSE_CODE%", "response_flags": "%RESPONSE_FLAGS%",
			"start_time": "%START_TIME%", "trace_id": "%TRACE_ID%", "upstream_address": "%UPSTREAM_REMOTE_ADDRESS%",
			"transport_failure_reason": "%UPSTREAM_TRANSPORT_FAILURE_REASON%", "user_agent": "%REQ(USER-AGENT)%",
			"sandbox_name":      "%CEL(filter_state['downstream_peer'].name)%",
			"sandbox_namespace": "%CEL(filter_state['downstream_peer'].namespace)%",
		}
		if len(fields) != len(want) {
			t.Fatalf("%s JSON label count = %d, want %d: %v", protocol, len(fields), len(want), fields)
		}
		for name, value := range want {
			if got := fields[name].GetStringValue(); got != value {
				t.Errorf("%s label %s = %q, want %q", protocol, name, got, value)
			}
		}
	}
}

func TestDefaultAccessLogPreservesOriginalSNI(t *testing.T) {
	fileLog := &fileaccesslogv3.FileAccessLog{}
	if err := defaultTelemetryProviders(nil).Provider("envoy").HTTPAccessLog.GetTypedConfig().UnmarshalTo(fileLog); err != nil {
		t.Fatal(err)
	}
	format := fileLog.GetLogFormat().GetJsonFormat().GetFields()["requested_server_name"].GetStringValue()
	testAccessLogSNI(t, format)
}

func testAccessLogSNI(t *testing.T, format string) {
	t.Helper()
	if !strings.HasPrefix(format, "%CEL(") || !strings.HasSuffix(format, ")%") {
		t.Fatalf("SNI format = %q, want CEL", format)
	}
	environment, err := cel.NewEnv(
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.BytesType)),
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
			if got.Value() != tt.want {
				t.Errorf("SNI = %v, want %q", got.Value(), tt.want)
			}
		})
	}
}
