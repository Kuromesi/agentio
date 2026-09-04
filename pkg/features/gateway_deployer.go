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

package features

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/env"
)

var (
	EnableGatewayDeployer = env.Register(
		"AGENTIO_ENABLE_GATEWAY_DEPLOYER",
		false,
		"If true, run the Agentio Gateway API deployment controller that provisions egress gateway Deployments.",
	).Get()
	GatewayLeaseName = env.Register(
		"AGENTIO_GATEWAY_LEASE_NAME",
		"agentiod-gateway-deployer-leader",
		"Lease electing the single replica running the gateway deployment controller.",
	).Get()
)

func validateGatewayDeployer() error {
	if EnableGatewayDeployer && strings.TrimSpace(GatewayLeaseName) == "" {
		return fmt.Errorf("gateway deployer lease name is required")
	}
	return nil
}
