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
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	"github.com/openkruise/agentio/pkg/model"
)

const fileAccessLogName = "envoy.access_loggers.file"

// DenialReasonFilterStateKey carries a gateway policy rejection reason for logs.
const DenialReasonFilterStateKey = "io.kruise.egress_denial_reason"

// The TLS termination chain shares the original ClientHello SNI with the
// plaintext internal listener. Keep it separate from the HTTP authority, which
// can differ (for example, an explicit proxy CONNECT target).
var defaultAccessLogLabels = map[string]string{
	"scheme":                         "%REQ(:SCHEME)%",
	"original_destination":           "%DOWNSTREAM_LOCAL_ADDRESS%",
	"upstream_host":                  "%UPSTREAM_HOST%",
	"denial_reason":                  "%FILTER_STATE(" + DenialReasonFilterStateKey + ":PLAIN)%",
	"response_code_details":          "%RESPONSE_CODE_DETAILS%",
	"connection_termination_details": "%CONNECTION_TERMINATION_DETAILS%",
	"log_type":                       "%ACCESS_LOG_TYPE%",

	"authority_for":            "%REQ(:AUTHORITY)%",
	"bytes_received":           "%BYTES_RECEIVED%",
	"bytes_sent":               "%BYTES_SENT%",
	"downstream_address":       "%DOWNSTREAM_REMOTE_ADDRESS%",
	"duration":                 "%DURATION%",
	"method":                   "%REQ(:METHOD)%",
	"path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
	"protocol":                 "%PROTOCOL%",
	"request_id":               "%REQ(X-REQUEST-ID)%",
	"requested_server_name":    "%CEL('io.kruise.outer_sni' in filter_state ? string(filter_state['io.kruise.outer_sni']) : connection.requested_server_name)%",
	"response_code":            "%RESPONSE_CODE%",
	"response_flags":           "%RESPONSE_FLAGS%",
	"start_time":               "%START_TIME%",
	"trace_id":                 "%TRACE_ID%",
	"upstream_address":         "%UPSTREAM_REMOTE_ADDRESS%",
	"transport_failure_reason": "%UPSTREAM_TRANSPORT_FAILURE_REASON%",
	"user_agent":               "%REQ(USER-AGENT)%",
	"sandbox_name":             "%CEL(filter_state['downstream_peer'].name)%",
	"sandbox_namespace":        "%CEL(filter_state['downstream_peer'].namespace)%",
}

// defaultTelemetryProviders returns a fresh provider graph with the gateway's
// format applied to the built-in envoy logger. Callers may mutate it safely.
func defaultTelemetryProviders(format *configv1.AccessLogFormat) model.TelemetryProviders {
	fields := make(map[string]*structpb.Value, len(defaultAccessLogLabels))
	for name, value := range defaultAccessLogLabels {
		fields[name] = structpb.NewStringValue(value)
	}
	fileLog := &fileaccesslogv3.FileAccessLog{
		Path: "/dev/stdout",
		AccessLogFormat: &fileaccesslogv3.FileAccessLog_LogFormat{LogFormat: &corev3.SubstitutionFormatString{
			Format:            &corev3.SubstitutionFormatString_JsonFormat{JsonFormat: &structpb.Struct{Fields: fields}},
			JsonFormatOptions: &corev3.JsonFormatOptions{SortProperties: false},
			OmitEmptyValues:   true,
		}},
	}
	switch {
	case format != nil && format.Text != nil:
		text := format.GetText()
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		fileLog.GetLogFormat().Format = &corev3.SubstitutionFormatString_TextFormatSource{
			TextFormatSource: &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: text}},
		}
		fileLog.GetLogFormat().OmitEmptyValues = false
		fileLog.GetLogFormat().JsonFormatOptions = nil
	case format.GetJson() != nil:
		fileLog.GetLogFormat().Format = &corev3.SubstitutionFormatString_JsonFormat{
			JsonFormat: proto.Clone(format.GetJson()).(*structpb.Struct),
		}
	}
	typed, err := protoutil.MarshalAny(fileLog)
	if err != nil {
		panic(err)
	}
	accessLog := &accesslogv3.AccessLog{
		Name:       fileAccessLogName,
		ConfigType: &accesslogv3.AccessLog_TypedConfig{TypedConfig: typed},
	}
	return model.TelemetryProviders{
		DefaultMetrics:       []string{"prometheus"},
		DefaultAccessLogging: []string{"envoy"},
		Providers: []model.TelemetryProvider{
			{Name: "envoy", HTTPAccessLog: accessLog, TCPAccessLog: proto.Clone(accessLog).(*accesslogv3.AccessLog)},
			{Name: "prometheus", Prometheus: true},
		},
	}
}
