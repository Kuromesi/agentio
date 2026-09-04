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

package kubernetes

import (
	"fmt"
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	"github.com/golang/protobuf/jsonpb"            //nolint:staticcheck // Agentio transfer schemas require jsonpb names and merge semantics.
	legacyproto "github.com/golang/protobuf/proto" //nolint:staticcheck // jsonpb accepts the legacy message interface.
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/model"
)

func decodeAgentioYAML(content, description string, target legacyproto.Message) error {
	jsonData, err := yaml.YAMLToJSON([]byte(content))
	if err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	if err := (&jsonpb.Unmarshaler{}).Unmarshal(strings.NewReader(string(jsonData)), target); err != nil {
		return fmt.Errorf("decode %s: %w", description, err)
	}
	return nil
}

// normalizeEgressServiceEntries validates data at the Kubernetes source
// boundary so invalid updates retain the last-known-good value.
func normalizeEgressServiceEntries(gateways []*configv1.EgressGateway) error {
	for gatewayIndex, gateway := range gateways {
		if gateway == nil {
			continue
		}
		normalized, err := model.NormalizeEgressGatewayServiceEntries(gateway)
		if err != nil {
			return fmt.Errorf("egressGateways[%d]: %w", gatewayIndex, err)
		}
		gateways[gatewayIndex] = normalized
	}
	return nil
}
