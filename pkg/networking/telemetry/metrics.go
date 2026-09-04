// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	stats "istio.io/api/envoy/extensions/stats"
)

const statsFilterName = "istio.stats"

var metricToPrometheusMetric = map[string]string{
	"REQUEST_COUNT":          "requests_total",
	"REQUEST_DURATION":       "request_duration_milliseconds",
	"REQUEST_SIZE":           "request_bytes",
	"RESPONSE_SIZE":          "response_bytes",
	"TCP_OPENED_CONNECTIONS": "tcp_connections_opened_total",
	"TCP_CLOSED_CONNECTIONS": "tcp_connections_closed_total",
	"TCP_SENT_BYTES":         "tcp_sent_bytes_total",
	"TCP_RECEIVED_BYTES":     "tcp_received_bytes_total",
	"GRPC_REQUEST_MESSAGES":  "request_messages_total",
	"GRPC_RESPONSE_MESSAGES": "response_messages_total",
}

func buildStatsFilters(configuration metricsConfig) (*hcmv3.HttpFilter, *listenerv3.Filter, error) {
	if configuration.ServerMetrics.Disabled {
		return nil, nil, nil
	}
	plugin := &stats.PluginConfig{
		Reporter:                  stats.Reporter_SERVER_GATEWAY,
		DisableHostHeaderFallback: true,
	}
	if configuration.ReportingInterval != nil {
		plugin.TcpReportingDuration = durationpb.New(*configuration.ReportingInterval)
	}
	for _, override := range configuration.ServerMetrics.Overrides {
		name := metricToPrometheusMetric[override.Name]
		if name == "" {
			name = override.Name
		}
		metric := &stats.MetricConfig{Name: name, Drop: override.Disabled, Dimensions: map[string]string{}}
		for _, tag := range override.Tags {
			if tag.Remove {
				metric.TagsToRemove = append(metric.TagsToRemove, tag.Name)
			} else {
				metric.Dimensions[tag.Name] = tag.Value
			}
		}
		plugin.Metrics = append(plugin.Metrics, metric)
	}
	typed, err := anypb.New(plugin)
	if err != nil {
		return nil, nil, err
	}
	return &hcmv3.HttpFilter{
			Name: statsFilterName, ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typed},
		}, &listenerv3.Filter{
			Name: statsFilterName, ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: proto.Clone(typed).(*anypb.Any)},
		}, nil
}
