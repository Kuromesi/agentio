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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"

	"github.com/openkruise/agentio/pkg/security/attestation"
)

var workloadIdentityOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57874, 5, 1}

// workloadIdentityExtension JSON-encodes the verified workload identity as a non-critical X.509 extension.
func workloadIdentityExtension(identity attestation.WorkloadIdentity) (pkix.Extension, error) {
	value, err := json.Marshal(identity)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: workloadIdentityOID, Value: value}, nil
}
