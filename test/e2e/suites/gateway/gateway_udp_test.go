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

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestGatewayConnectUDPConfig proves the pinned Envoy accepts the experimental
// CONNECT-UDP resources generated under AGENTIO_GATEWAY_ENABLE_UDP_PROXY. UDP
// traffic itself is not exercised: source Pods do not yet capture UDP to ztunnel.
func TestGatewayConnectUDPConfig(t *testing.T) {
	rig.RequireLive(t)
	environment := suite.Environment(t)

	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		for field, value := range map[string]string{
			"upgrade_type": "connect-udp",
			"name":         "agentio.udp_target",
			"cluster":      "agentio_udp_passthrough",
			"object_key":   "envoy.network.transport_socket.original_dst_address",
		} {
			if !containsJSONString(dump, field, value) {
				return fmt.Errorf("config_dump does not contain %s %q", field, value)
			}
		}
		return nil
	})
}

func containsJSONString(dump, field, value string) bool {
	compact := fmt.Sprintf(`"%s":"%s"`, field, value)
	pretty := fmt.Sprintf(`"%s": "%s"`, field, value)
	return strings.Contains(dump, compact) || strings.Contains(dump, pretty)
}
