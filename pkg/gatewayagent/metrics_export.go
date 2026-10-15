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
	"bufio"
	"io"
	"strings"
)

// Envoy adds its namespace to native module metrics. Rewrite only metric names,
// including their TYPE/HELP declarations, never label values or other metrics.
func copyGatewayMetrics(dst io.Writer, src io.Reader) error {
	reader := bufio.NewReader(src)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			// Do not append an interrupted sample to the agent's health metrics.
			return err
		}
		offset := 0
		for _, prefix := range []string{"# TYPE ", "# HELP "} {
			if strings.HasPrefix(line, prefix) {
				offset = len(prefix)
				break
			}
		}
		const namespace = "envoy_agentio_gateway_"
		name := line[offset:]
		if metric, ok := strings.CutPrefix(name, namespace); ok {
			end := strings.IndexAny(metric, "{ \t\r\n")
			if end >= 0 {
				switch metric[:end] {
				case "istio_requests_total", "istio_request_duration_milliseconds",
					"istio_request_duration_milliseconds_bucket", "istio_request_duration_milliseconds_sum",
					"istio_request_duration_milliseconds_count":
					line = line[:offset] + metric
					// The module pre-registers response codes; publish counters only after traffic.
					if offset == 0 && metric[:end] == "istio_requests_total" &&
						strings.TrimSpace(metric[strings.LastIndexByte(metric, '}')+1:]) == "0" {
						line = ""
					}
				}
			}
		}
		if _, writeErr := io.WriteString(dst, line); writeErr != nil {
			return writeErr
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
