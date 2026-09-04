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

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// GatewayCertificateAuthorizer is the Kubernetes gateway certificate policy
// view: an authenticated egress gateway may obtain MITM certificates only for
// the gateway key its identity owns and only when that gateway is registered
// in the conflict-free, source-merged Gateway collection.
type GatewayCertificateAuthorizer struct {
	gateways krt.Collection[model.Gateway]
}

func NewGatewayCertificateAuthorizer(
	gateways krt.Collection[model.Gateway],
) *GatewayCertificateAuthorizer {
	return &GatewayCertificateAuthorizer{gateways: gateways}
}

func (r *Registry) GatewayCertificateAuthorizer() *GatewayCertificateAuthorizer {
	return NewGatewayCertificateAuthorizer(r.Gateways)
}

func (a *GatewayCertificateAuthorizer) Authorize(scope model.ClientScope) error {
	if a == nil || a.gateways == nil {
		return fmt.Errorf("authorize gateway certificate: registry is not configured")
	}
	if scope.Class != model.ClientEgressGateway || scope.Principal.Kind != model.PrincipalServiceAccount ||
		scope.Principal.ServiceAccount.Namespace == "" || scope.Principal.ServiceAccount.ServiceAccount == "" {
		return fmt.Errorf("authorize gateway certificate: only authenticated egress gateways are allowed")
	}
	if scope.GatewayKey != scope.Principal.ServiceAccount.Namespace+"/"+scope.Principal.ServiceAccount.ServiceAccount {
		return fmt.Errorf("authorize gateway certificate: identity %s does not own %s", scope.Principal.String(), scope.GatewayKey)
	}
	gateway := a.gateways.GetKey(scope.GatewayKey)
	if gateway != nil && gateway.ValidateForUse() == nil {
		return nil
	}
	return fmt.Errorf("authorize gateway certificate: gateway %s is not registered, valid, or conflict-free", scope.GatewayKey)
}
