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
package filter

import (
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// hopByHopNames are rejected for every kind because Envoy owns connection
// semantics itself (RFC 9110 §7.6.1); content-encoding is included because a
// header-only mutation cannot re-encode a body, so changing it misinforms the
// recipient.
var hopByHopNames = map[string]struct{}{
	"connection":         {},
	"keep-alive":         {},
	"proxy-connection":   {},
	"upgrade":            {},
	"te":                 {},
	"trailer":            {},
	"proxy-authenticate": {},
	"content-encoding":   {},
}

// framingNames may be removed but not set or added: a name written without a
// matching body update could corrupt HTTP/1 framing.
var framingNames = map[string]struct{}{
	"content-length":    {},
	"transfer-encoding": {},
}

// ValidateHeaderName reports whether a filter may apply kind to name and
// returns the lower-cased name to use.
//
// It governs names arriving from configuration or from a remote service, and is
// deliberately not wired into the fold or translate path: it rejects
// pseudo-headers because ValidHeaderFieldName rejects ":", while the engine's
// own helpers (SetPath) legitimately rewrite them.
//
// Error strings are unprefixed so callers can qualify them with their own
// phase or index; headermutation's messages are built by wrapping these.
func ValidateHeaderName(kind HeaderOpKind, name string) (string, error) {
	if !httpguts.ValidHeaderFieldName(name) {
		return "", fmt.Errorf("header %q has an invalid name", name)
	}
	normalized := strings.ToLower(name)
	if normalized == "host" {
		return "", fmt.Errorf("header %q cannot modify Host", name)
	}
	// Envoy ignores all names with the reserved "x-envoy" prefix.
	if strings.HasPrefix(normalized, "x-envoy") {
		return "", fmt.Errorf("header %q is reserved by Envoy and would be ignored", name)
	}
	if _, forbidden := hopByHopNames[normalized]; forbidden {
		return "", fmt.Errorf("header %q is connection-scoped and cannot be mutated", name)
	}
	if _, framing := framingNames[normalized]; framing && kind != HeaderRemove {
		return "", fmt.Errorf("header %q controls message framing and can only be removed", name)
	}
	return normalized, nil
}
