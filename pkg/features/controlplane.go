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
	TokenAudience = env.Register(
		"AGENTIO_TOKEN_AUDIENCE",
		"istio-ca",
		"Audience a client token must carry to be accepted.",
	).Get()
	ServiceName = env.Register(
		"AGENTIO_SERVICE_NAME",
		"agentiod",
		"Kubernetes service name placed in the xDS server certificate.",
	).Get()
	ZTunnelAccount = env.Register(
		"AGENTIO_TRUSTED_NODE_ACCOUNTS",
		"",
		"If set, the list of service accounts that are allowed to use node authentication for CSRs. "+
			"Node authentication allows an identity to create CSRs on behalf of other identities, but only if there is a pod "+
			"running on the same node with that identity. This is intended for use with node proxies.",
	).Get()
	AgentioConfigMapName = env.Register(
		"AGENTIO_CONFIGMAP_NAME",
		"agentio-config",
		"ConfigMap name of Agentio configuration.",
	).Get()
	PrimaryAgentioConfigMapName = env.Register(
		"AGENTIO_PRIMARY_CONFIGMAP_NAME",
		"agentio-config-primary",
		"ConfigMap name of primary Agentio configuration. Empty disables the primary overlay.",
	).Get()
	IgnoreResources = env.Register(
		"AGENTIO_IGNORE_RESOURCES",
		"",
		"Comma-separated CRD names excluded from the CRD watcher; a \"*.\" prefix excludes a whole group by suffix (e.g. \"*.istio.io\").",
	).Get()
	IncludeResources = env.Register(
		"AGENTIO_INCLUDE_RESOURCES",
		"",
		"Comma-separated CRD names always admitted to the CRD watcher, overriding AGENTIO_IGNORE_RESOURCES; same \"*.\" group-suffix syntax.",
	).Get()
	EnableDebugOnHTTP = env.Register(
		"AGENTIO_ENABLE_DEBUG_ON_HTTP",
		true,
		"Enable authenticated debug handlers on the monitoring HTTP listener.",
	).Get()
)

func validateControlPlane() error {
	if strings.TrimSpace(TokenAudience) == "" {
		return fmt.Errorf("token audience is required")
	}
	return nil
}
