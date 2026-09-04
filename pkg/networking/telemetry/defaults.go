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
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

const fileAccessLogName = "envoy.access_loggers.file"

var chartAccessLogLabels = map[string]string{
	"authority_for":            "%REQ(:AUTHORITY)%",
	"bytes_received":           "%BYTES_RECEIVED%",
	"bytes_sent":               "%BYTES_SENT%",
	"downstream_address":       "%DOWNSTREAM_REMOTE_ADDRESS%",
	"duration":                 "%DURATION%",
	"method":                   "%REQ(:METHOD)%",
	"path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
	"protocol":                 "%PROTOCOL%",
	"request_id":               "%REQ(X-REQUEST-ID)%",
	"requested_server_name":    "%REQUESTED_SERVER_NAME%",
	"response_code":            "%RESPONSE_CODE%",
	"response_flags":           "%RESPONSE_FLAGS%",
	"start_time":               "%START_TIME%",
	"trace_id":                 "%TRACE_ID%",
	"upstream_address":         "%DOWNSTREAM_LOCAL_ADDRESS%",
	"transport_failure_reason": "%UPSTREAM_TRANSPORT_FAILURE_REASON%",
	"user_agent":               "%REQ(USER-AGENT)%",
	"sandbox_name":             "%CEL(filter_state['downstream_peer'].name)%",
	"sandbox_namespace":        "%CEL(filter_state['downstream_peer'].namespace)%",
}

// defaultTelemetryProviders returns a fresh provider graph equivalent to the Agentio
// chart MeshConfig defaults. Callers may mutate the result safely.
func defaultTelemetryProviders() model.TelemetryProviders {
	fields := make(map[string]*structpb.Value, len(chartAccessLogLabels))
	for name, value := range chartAccessLogLabels {
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
	typed, err := anypb.New(fileLog)
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
