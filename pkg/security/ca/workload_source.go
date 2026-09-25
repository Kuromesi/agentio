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
	"fmt"
	"strconv"
	"strings"

	"github.com/openkruise/agentio/pkg/model"
)

func parseWorkloadSourceOID(value string) (asn1.ObjectIdentifier, error) {
	if value == "" {
		return nil, nil
	}
	// A private enterprise OID cannot override a standard extension such as SAN.
	if !strings.HasPrefix(value, "1.3.6.1.4.1.") {
		return nil, fmt.Errorf("workload source extension requires a private enterprise OID")
	}
	parts := strings.Split(value, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		// Go's X.509 parser accepts at most 31-bit OID components.
		arc, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid workload source extension OID %q", value)
		}
		oid[i] = int(arc)
	}
	return oid, nil
}

// workloadSourceExtension encodes only the source accepted by the authorizer.
// URI SAN remains the principal; no CSR extensions or Sandbox bindings are copied.
func workloadSourceExtension(oid asn1.ObjectIdentifier, source model.SourceRef) (pkix.Extension, error) {
	value, err := asn1.Marshal(struct {
		Registry string `asn1:"utf8"`
		Key      string `asn1:"utf8"`
	}{Registry: source.Registry, Key: source.Key})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oid, Value: value}, nil
}
