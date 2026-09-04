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

// Attestation names the infrastructure that authenticated a client.
type Attestation string

const AttestationKubernetes Attestation = "kubernetes"

// PeerIdentity contains the identity and attestation-bound attributes established
// by transport authentication.
type PeerIdentity struct {
	Principal  Principal
	AttestedBy Attestation
	// Kubernetes holds Kubernetes attestation extras; other attestations ignore it.
	Kubernetes KubernetesPeer
}

// KubernetesPeer is the Kubernetes attestation payload of a PeerIdentity: the pod and
// node bindings a bound service-account token proves.
type KubernetesPeer struct {
	WorkloadName string
	WorkloadUID  string
	NodeName     string
}
