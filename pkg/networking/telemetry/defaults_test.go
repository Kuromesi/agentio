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
	"testing"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
)

func TestDefaultProvidersMatchAgentioChart(t *testing.T) {
	defaults := defaultTelemetryProviders()
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
			"authority_for": "%REQ(:AUTHORITY)%", "bytes_received": "%BYTES_RECEIVED%", "bytes_sent": "%BYTES_SENT%",
			"downstream_address": "%DOWNSTREAM_REMOTE_ADDRESS%", "duration": "%DURATION%", "method": "%REQ(:METHOD)%",
			"path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%", "protocol": "%PROTOCOL%", "request_id": "%REQ(X-REQUEST-ID)%",
			"requested_server_name": "%REQUESTED_SERVER_NAME%", "response_code": "%RESPONSE_CODE%", "response_flags": "%RESPONSE_FLAGS%",
			"start_time": "%START_TIME%", "trace_id": "%TRACE_ID%", "upstream_address": "%DOWNSTREAM_LOCAL_ADDRESS%",
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
