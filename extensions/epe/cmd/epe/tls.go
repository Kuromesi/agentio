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
package main

import (
	"crypto/tls"
	"errors"
	"strings"

	"istio.io/istio/extensions/epe/pkg/certs"
)

// extProcTLS is the serving material built from the --tls-* flags for the
// ext-proc listener.
type extProcTLS struct {
	// Secure reports whether the listener serves TLS at all; false means
	// plaintext (the default when no flags are set).
	Secure bool
	// Provider supplies the hot-rotating certificate material.
	Provider certs.Provider
	// Options carries the mTLS / peer-identity options for ServerTLSConfig.
	Options []certs.Option
	// SPIFFEAllowList is non-nil when --peer-spiffe-ids is set; its contents
	// can be swapped at runtime via Set.
	SPIFFEAllowList *certs.SPIFFEAllowList
}

// buildExtProcTLS validates the TLS flag combination and builds the ext-proc
// serving material. All-empty inputs mean plaintext serving.
func buildExtProcTLS(certPath, keyPath, caPath, spiffeIDs string) (*extProcTLS, error) {
	if certPath == "" && keyPath == "" && caPath == "" && spiffeIDs == "" {
		return &extProcTLS{}, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("--tls-cert-path and --tls-key-path must be set together")
	}
	if caPath == "" && spiffeIDs != "" {
		return nil, errors.New("--peer-spiffe-ids requires --tls-ca-path: SPIFFE identity " +
			"verification is only sound on CA-verified client chains")
	}

	result := &extProcTLS{Secure: true}
	if caPath != "" {
		result.Options = append(result.Options, certs.WithClientAuth(tls.RequireAndVerifyClientCert))
	}
	if spiffeIDs != "" {
		ids := splitSPIFFEIDs(spiffeIDs)
		if len(ids) == 0 {
			return nil, errors.New("--peer-spiffe-ids contains no SPIFFE IDs")
		}
		list, err := certs.NewSPIFFEAllowList(ids...)
		if err != nil {
			return nil, err
		}
		result.SPIFFEAllowList = list
		result.Options = append(result.Options, certs.WithPeerVerifier(list.VerifyPeer))
	}

	provider, err := certs.FromFiles(certPath, keyPath, caPath)
	if err != nil {
		return nil, err
	}
	// FromFiles loads only cert/key eagerly; the CA bundle is read lazily on
	// each handshake. Probe it once so a missing or invalid --tls-ca-path
	// fails at startup instead of failing every handshake at runtime.
	if caPath != "" {
		if _, err := provider.RootCAs(); err != nil {
			return nil, err
		}
	}
	result.Provider = provider
	return result, nil
}

// splitSPIFFEIDs splits the comma-separated flag value, trimming whitespace
// and dropping empty entries.
func splitSPIFFEIDs(raw string) []string {
	var ids []string
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
