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
	"reflect"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	uuidv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/request_id/uuid/v3"
	tracingv3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	stats "istio.io/api/envoy/extensions/stats"

	"github.com/openkruise/agentio/pkg/model"
)

func TestBuildPrometheus(t *testing.T) {
	disabled := true
	interval := 17 * time.Second
	policy := buildValue(t, []model.TelemetryMetrics{{
		Providers:         []string{"prometheus"},
		ReportingInterval: &interval,
		Overrides: []model.TelemetryMetricOverride{
			{
				Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer},
				Disabled: &disabled,
				TagOverrides: map[string]model.TelemetryMetricTagOverride{
					"remove": {Operation: model.TelemetryTagRemove},
					"upsert": {Operation: model.TelemetryTagUpsert, Value: "value"},
				},
			},
			{
				Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricCustom, Name: "custom", Mode: model.TelemetryModeClientAndServer},
			},
		},
	}}, nil, nil)

	output, err := Build(Inputs{Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", Telemetry: []model.Telemetry{policy}})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.HTTPFilters) != 1 || len(output.TCPFilters) != 1 {
		t.Fatalf("stats filters = HTTP %d, TCP %d", len(output.HTTPFilters), len(output.TCPFilters))
	}
	if output.HTTPFilters[0].Name != statsFilterName || output.TCPFilters[0].Name != statsFilterName {
		t.Fatalf("stats filter names = %q, %q", output.HTTPFilters[0].Name, output.TCPFilters[0].Name)
	}
	configuration := new(stats.PluginConfig)
	if err := output.HTTPFilters[0].GetTypedConfig().UnmarshalTo(configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Reporter != stats.Reporter_SERVER_GATEWAY || !configuration.DisableHostHeaderFallback {
		t.Fatalf("stats reporter/fallback = %v/%v", configuration.Reporter, configuration.DisableHostHeaderFallback)
	}
	if configuration.GetTcpReportingDuration().AsDuration() != interval {
		t.Fatalf("reporting interval = %v", configuration.GetTcpReportingDuration())
	}
	wantMetrics := []*stats.MetricConfig{
		{Name: "requests_total", Dimensions: map[string]string{"upsert": "value"}, TagsToRemove: []string{"remove"}, Drop: true},
		{Name: "custom", Dimensions: map[string]string{}},
	}
	if len(configuration.Metrics) != len(wantMetrics) || !proto.Equal(configuration.Metrics[0], wantMetrics[0]) || !proto.Equal(configuration.Metrics[1], wantMetrics[1]) {
		t.Fatalf("metrics = %v, want %v", configuration.Metrics, wantMetrics)
	}
	if proto.Equal(output.HTTPFilters[0].GetTypedConfig(), output.TCPFilters[0].GetTypedConfig()) == false {
		t.Fatal("HTTP and TCP stats payloads differ")
	}
}

func TestBuildAccessLoggingAndTracing(t *testing.T) {
	filter := "response.code >= 500"
	sampling := 12.5
	requestID := false
	enableIstioTags := false
	policy := buildValue(t, nil, []model.TelemetryTracing{{
		Mode: model.TelemetryModeServer, Providers: []string{"trace"}, RandomSamplingPercentage: &sampling,
		UseRequestIDForTraceSampling: &requestID, EnableIstioTags: &enableIstioTags,
		CustomTags: map[string]model.TelemetryTracingTag{
			"a-env":       {Kind: model.TelemetryTracingTagEnvironment, Name: "POD_NAME", DefaultValue: "unknown"},
			"b-header":    {Kind: model.TelemetryTracingTagHeader, Name: "x-user", DefaultValue: "anonymous"},
			"c-literal":   {Kind: model.TelemetryTracingTagLiteral, Value: "literal"},
			"d-formatter": {Kind: model.TelemetryTracingTagFormatter, Value: "%REQ(:METHOD)%"},
		},
	}}, []model.TelemetryAccessLogging{{
		Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &filter,
	}})
	tracerAny, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	base := defaultTelemetryProviders()
	baseTrace := model.TelemetryProvider{
		Name: "trace",
		Tracing: &model.TelemetryTracingProvider{
			Provider:          &tracev3.Tracing_Http{Name: "envoy.tracers.test", ConfigType: &tracev3.Tracing_Http_TypedConfig{TypedConfig: tracerAny}},
			SpawnUpstreamSpan: true,
			MaxPathTagLength:  256,
		},
		Clusters: []*clusterv3.Cluster{{Name: "trace-cluster"}},
	}
	overrides := &model.TelemetryProviderOverrides{Providers: []model.TelemetryProvider{baseTrace}}
	output, err := Build(Inputs{
		Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", Telemetry: []model.Telemetry{policy}, ProviderOverrides: overrides,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.HTTPAccessLogs) != 1 || len(output.TCPAccessLogs) != 1 {
		t.Fatalf("access logs = HTTP %d TCP %d", len(output.HTTPAccessLogs), len(output.TCPAccessLogs))
	}
	if output.HTTPAccessLogs[0] == base.Provider("envoy").HTTPAccessLog || output.TCPAccessLogs[0] == base.Provider("envoy").TCPAccessLog {
		t.Fatal("provider access-log template was not cloned")
	}
	assertCELFilter(t, output.HTTPAccessLogs[0], filter)
	assertCELFilter(t, output.TCPAccessLogs[0], filter)

	if output.Tracing == nil || output.Tracing.Provider.GetName() != "envoy.tracers.test" {
		t.Fatalf("tracing provider = %#v", output.Tracing)
	}
	if output.Tracing.RandomSampling.GetValue() != sampling || output.Tracing.ClientSampling.GetValue() != 100 || output.Tracing.OverallSampling.GetValue() != 100 {
		t.Fatalf("sampling = %#v", output.Tracing)
	}
	if output.Tracing.GetMaxPathTagLength().GetValue() != 256 || !output.Tracing.GetSpawnUpstreamSpan().GetValue() {
		t.Fatalf("provider tracing options = %#v", output.Tracing)
	}
	if got := tracingTagNames(output.Tracing.CustomTags); !reflect.DeepEqual(got, []string{"a-env", "b-header", "c-literal", "d-formatter"}) {
		t.Fatalf("tracing tags = %v", got)
	}
	if output.Tracing.CustomTags[0].GetEnvironment().GetName() != "POD_NAME" || output.Tracing.CustomTags[1].GetRequestHeader().GetName() != "x-user" || output.Tracing.CustomTags[2].GetLiteral().GetValue() != "literal" || output.Tracing.CustomTags[3].GetValue() != "%REQ(:METHOD)%" {
		t.Fatalf("tracing tag variants = %#v", output.Tracing.CustomTags)
	}
	uuid := new(uuidv3.UuidRequestIdConfig)
	if err := output.RequestIDExtension.GetTypedConfig().UnmarshalTo(uuid); err != nil {
		t.Fatal(err)
	}
	if uuid.GetUseRequestIdForTraceSampling().GetValue() {
		t.Fatalf("request-ID sampling = %v", uuid.GetUseRequestIdForTraceSampling())
	}
	if len(output.Clusters) != 1 || output.Clusters[0].Name != "trace-cluster" || output.Clusters[0] == baseTrace.Clusters[0] {
		t.Fatalf("provider clusters = %#v", output.Clusters)
	}
}

func TestBuildStandardMetricNamesMatchAgentio(t *testing.T) {
	policy := buildValue(t, []model.TelemetryMetrics{{
		Overrides: []model.TelemetryMetricOverride{
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "GRPC_REQUEST_MESSAGES", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "GRPC_RESPONSE_MESSAGES", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_DURATION", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_SIZE", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "RESPONSE_SIZE", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "TCP_CLOSED_CONNECTIONS", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "TCP_OPENED_CONNECTIONS", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "TCP_RECEIVED_BYTES", Mode: model.TelemetryModeServer}},
			{Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "TCP_SENT_BYTES", Mode: model.TelemetryModeServer}},
		},
	}}, nil, nil)

	output, err := Build(Inputs{
		Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", Telemetry: []model.Telemetry{policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration := new(stats.PluginConfig)
	if len(output.HTTPFilters) != 1 {
		t.Fatalf("HTTP stats filters = %d, want 1", len(output.HTTPFilters))
	}
	if err := output.HTTPFilters[0].GetTypedConfig().UnmarshalTo(configuration); err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(configuration.Metrics))
	for index, metric := range configuration.Metrics {
		got[index] = metric.Name
	}
	want := []string{
		"request_messages_total",
		"response_messages_total",
		"requests_total",
		"request_duration_milliseconds",
		"request_bytes",
		"response_bytes",
		"tcp_connections_closed_total",
		"tcp_connections_opened_total",
		"tcp_received_bytes_total",
		"tcp_sent_bytes_total",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("standard metric names = %v, want %v", got, want)
	}
}

func TestBuildOmitsDisabledServerSignals(t *testing.T) {
	disabled := true
	policy := buildValue(t, []model.TelemetryMetrics{{
		Overrides: []model.TelemetryMetricOverride{{
			Match: model.TelemetryMetricSelector{Kind: model.TelemetryMetricAll, Mode: model.TelemetryModeServer}, Disabled: &disabled,
		}},
	}}, []model.TelemetryTracing{{
		Mode: model.TelemetryModeServer, Providers: []string{"trace"}, DisableSpanReporting: &disabled,
	}}, []model.TelemetryAccessLogging{{
		Mode: model.TelemetryModeServer, Disabled: &disabled,
	}})
	output, err := Build(Inputs{
		Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", Telemetry: []model.Telemetry{policy},
		ProviderOverrides: &model.TelemetryProviderOverrides{Providers: []model.TelemetryProvider{{
			Name: "trace", Tracing: testTracingProvider(t),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.HTTPFilters) != 0 || len(output.TCPFilters) != 0 ||
		len(output.HTTPAccessLogs) != 0 || len(output.TCPAccessLogs) != 0 ||
		output.Tracing != nil || output.RequestIDExtension != nil || len(output.Clusters) != 0 {
		t.Fatalf("disabled signals produced output: %#v", output)
	}
}

func TestBuildRejectsUnknownSignalProvider(t *testing.T) {
	tests := []struct {
		name   string
		policy model.Telemetry
	}{
		{name: "unknown metrics provider", policy: buildValue(t, []model.TelemetryMetrics{{Providers: []string{"missing"}}}, nil, nil)},
		{name: "unknown access logging provider", policy: buildValue(t, nil, nil, []model.TelemetryAccessLogging{{
			Mode: model.TelemetryModeServer, Providers: []string{"missing"},
		}})},
		{name: "unknown tracing provider", policy: buildValue(t, nil, []model.TelemetryTracing{{
			Mode: model.TelemetryModeServer, Providers: []string{"missing"},
		}}, nil)},
		{name: "access logger used for metrics", policy: buildValue(t, []model.TelemetryMetrics{{Providers: []string{"envoy"}}}, nil, nil)},
		{name: "metrics provider used for access logging", policy: buildValue(t, nil, nil, []model.TelemetryAccessLogging{{
			Mode: model.TelemetryModeServer, Providers: []string{"prometheus"},
		}})},
		{name: "metrics provider used for tracing", policy: buildValue(t, nil, []model.TelemetryTracing{{
			Mode: model.TelemetryModeServer, Providers: []string{"prometheus"},
		}}, nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Build(Inputs{
				Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", Telemetry: []model.Telemetry{test.policy},
			}); err == nil {
				t.Fatal("expected signal provider failure")
			}
		})
	}
}

func assertCELFilter(t *testing.T, accessLog *accesslogv3.AccessLog, expression string) {
	t.Helper()
	extension := accessLog.GetFilter().GetExtensionFilter()
	if extension.GetName() != celFilterName {
		t.Fatalf("CEL filter name = %q", extension.GetName())
	}
	configuration := new(celv3.ExpressionFilter)
	if err := extension.GetTypedConfig().UnmarshalTo(configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Expression != expression {
		t.Fatalf("CEL expression = %q", configuration.Expression)
	}
}

func tracingTagNames(tags []*tracingv3.CustomTag) []string {
	result := make([]string, len(tags))
	for index := range tags {
		result[index] = tags[index].Tag
	}
	return result
}

func testTelemetryGateway() model.Gateway {
	return model.Gateway{Namespace: "bookinfo", Name: "egress", Source: model.GatewaySourceAgentioConfig, Config: &configv1.EgressGateway{}}
}

func buildValue(t *testing.T, metrics []model.TelemetryMetrics, tracing []model.TelemetryTracing, logging []model.TelemetryAccessLogging) model.Telemetry {
	t.Helper()
	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "bookinfo", Name: "telemetry", Source: "agentio-system/source",
	}, []string{"bookinfo/egress"}, metrics, tracing, logging)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
