// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// NoMaterial returns a Provider that holds nothing: it presents no client
// identity and no custom trust anchors, so a client verifies against the system
// trust store. It is the "none" source, and the resting state for a caller that
// has no certificate configuration at all.
func NoMaterial() Provider { return noMaterial{} }

type noMaterial struct{}

// GetCertificate fails: a server has nothing to present. Returning an empty
// certificate would make crypto/tls treat it as real and index its empty chain.
func (noMaterial) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("certs: no certificate material is configured")
}

// GetClientCertificate presents no identity, which is a completable handshake.
func (noMaterial) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{}, nil
}

func (noMaterial) RootCAs() (*x509.CertPool, error) { return nil, nil }
