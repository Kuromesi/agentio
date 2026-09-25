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

package ca

import (
	"fmt"

	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// Only the absence of explicit target metadata selects this old request path.
// Malformed metadata and CSR mismatches are never retried through compatibility.
func legacyRequestIdentity(caller model.PeerIdentity, trustDomain string) (model.Principal, error) {
	if caller.AttestedBy != model.AttestationKubernetes {
		return model.Principal{}, fmt.Errorf("an explicit certificate identity is required")
	}
	if err := caller.Kubernetes.Validate(); err != nil {
		return model.Principal{}, err
	}
	return podsource.ServiceAccountPrincipal(trustDomain, caller.Kubernetes.Namespace, caller.Kubernetes.ServiceAccount)
}
