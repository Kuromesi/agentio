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

package gatewayagent

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestGatewayMetricNames(t *testing.T) {
	input := "# TYPE envoy_agentio_gateway_istio_requests_total counter\n" +
		"# HELP envoy_agentio_gateway_istio_requests_total Requests\n" +
		"envoy_agentio_gateway_istio_requests_total{response_code=\"418\"} 3\n" +
		"envoy_agentio_gateway_istio_request_duration_milliseconds_bucket{le=\"1\"} 2\n" +
		"envoy_agentio_gateway_istio_request_duration_milliseconds_sum 7\n" +
		"envoy_agentio_gateway_istio_request_duration_milliseconds_count 3\n"
	untouched := "envoy_other{label=\"envoy_agentio_gateway_istio_requests_total\"} 1\n" +
		"envoy_agentio_gateway_istio_requests_total_extra 1\n" +
		"envoy_large{label=\"" + strings.Repeat("a", 100000) + "\"} 1"
	var output strings.Builder
	if err := copyGatewayMetrics(&output, strings.NewReader(input+untouched)); err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(input, "envoy_agentio_gateway_", "") + untouched
	if output.String() != want {
		t.Fatal("metric names or label values changed incorrectly")
	}
}

func TestGatewayMetricReadFailure(t *testing.T) {
	expected := errors.New("interrupted admin response")
	if err := copyGatewayMetrics(io.Discard, failingMetricsReader{expected}); !errors.Is(err, expected) {
		t.Fatalf("error = %v", err)
	}
}

func TestGatewayMetricsOmitUnusedResponseCodes(t *testing.T) {
	const prefix = "envoy_agentio_gateway_"
	input := "# TYPE " + prefix + "istio_requests_total counter\n" +
		"# HELP " + prefix + "istio_requests_total Requests\n" +
		prefix + "istio_requests_total{response_code=\"445\"} 0\n" +
		prefix + "istio_requests_total{response_code=\"452\"} 16\n" +
		prefix + "istio_requests_total{response_code=\"0\"} 1\n" +
		prefix + "istio_request_duration_milliseconds_bucket{le=\"1\"} 0\n" +
		prefix + "istio_request_duration_milliseconds_sum 0\n" +
		prefix + "istio_request_duration_milliseconds_count 0\n" +
		"envoy_other{response_code=\"445\"} 0\n" +
		prefix + "istio_requests_total_extra 0\n" +
		prefix + "istio_requests_total{response_code=\"446\"} 0"
	want := "# TYPE istio_requests_total counter\n" +
		"# HELP istio_requests_total Requests\n" +
		"istio_requests_total{response_code=\"452\"} 16\n" +
		"istio_requests_total{response_code=\"0\"} 1\n" +
		"istio_request_duration_milliseconds_bucket{le=\"1\"} 0\n" +
		"istio_request_duration_milliseconds_sum 0\n" +
		"istio_request_duration_milliseconds_count 0\n" +
		"envoy_other{response_code=\"445\"} 0\n" +
		prefix + "istio_requests_total_extra 0\n"
	var output strings.Builder
	if err := copyGatewayMetrics(&output, strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if output.String() != want {
		t.Fatalf("unexpected exported metrics:\n%s", output.String())
	}
}

type failingMetricsReader struct{ err error }

func (r failingMetricsReader) Read([]byte) (int, error) { return 0, r.err }
