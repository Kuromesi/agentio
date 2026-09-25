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

package model

import "fmt"

// Attestation names the infrastructure that authenticated a client.
type Attestation string

const AttestationKubernetes Attestation = "kubernetes"

// PeerIdentity contains only verified authentication evidence. The registry
// resolves it to the Workloads whose certificate identities the caller may use.
type PeerIdentity struct {
	AttestedBy Attestation
	Kubernetes KubernetesPeer
}

// KubernetesPeer is produced by TokenReview, independently of certificate naming.
// Pod bindings are required for workload issuance and xDS ownership resolution.
type KubernetesPeer struct {
	Namespace      string
	ServiceAccount string
	WorkloadName   string
	WorkloadUID    string
	NodeName       string
}

func (p KubernetesPeer) Validate() error {
	if p.Namespace == "" || p.ServiceAccount == "" {
		return fmt.Errorf("Kubernetes namespace and service account are required")
	}
	return nil
}
