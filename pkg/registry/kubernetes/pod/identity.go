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

package pod

import (
	"strings"

	"github.com/openkruise/agentio/pkg/model"
)

// ServiceAccountPrincipal encodes the logical certificate identity for Kubernetes.
func ServiceAccountPrincipal(trustDomain, namespace, account string) (model.Principal, error) {
	return model.NewPrincipal(trustDomain, "ns/"+namespace+"/sa/"+account)
}

// ServiceAccountFromPrincipal projects Kubernetes identities for older WDS clients.
func ServiceAccountFromPrincipal(principal model.Principal) (namespace, account string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(principal.String(), "spiffe://"+principal.TrustDomain()+"/"), "/")
	if len(parts) == 4 && parts[0] == "ns" && parts[2] == "sa" {
		return parts[1], parts[3], true
	}
	return "", "", false
}
