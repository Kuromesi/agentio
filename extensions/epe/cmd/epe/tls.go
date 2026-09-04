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
	"fmt"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certsource"
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
// serving material. All-empty inputs mean plaintext serving. stop bounds the
// certificate reload machinery.
func buildExtProcTLS(certPath, keyPath, caPath, spiffeIDs string, stop <-chan struct{}) (*extProcTLS, error) {
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

	provider, err := certsource.FromFiles(certPath, keyPath, caPath, stop)
	if err != nil {
		return nil, err
	}
	// Probe the CA bundle once so a missing or invalid --tls-ca-path fails at
	// startup instead of failing every handshake at runtime.
	//
	// The probe checks the pool, not just the error: an unreadable or
	// unparseable bundle resolves to nil, meaning "use the system trust store",
	// so an error alone no longer detects it. A nil pool is still refused
	// per-connection by ServerTLSConfig when client certificates are verified —
	// this only moves that refusal back to startup, where it is actionable.
	if caPath != "" {
		pool, err := provider.RootCAs()
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, fmt.Errorf("no usable CA certificates in %s", caPath)
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
