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
	"context"
	"encoding/base64"
	"encoding/json"

	"k8s.io/apimachinery/pkg/types"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// Peer is the downstream caller: the Sandbox pod and its agent credential,
// resolved from filter_state and source.address. Mirrors the source/Peer
// half of Envoy's AttributeContext. Never expression-visible; the
// expression vocabulary lives in the inputs package.
//
// Peer and SandboxToken live in the contract package itself because Stream
// embeds Peer, so anything imported here lands in every filter's dependency
// closure (see the arch guards).
type Peer struct {
	// Pod identifies the source pod from filter_state['agentio.workload.name'] and
	// filter_state['agentio.workload.namespace'], falling back per field to
	// filter_state['downstream_peer']. Either half may be empty; see Valid.
	Pod types.NamespacedName
	// IP is the source pod IP, extracted from Envoy's source.address
	// attribute. Empty string when the attribute is absent (E2E test
	// fallback).
	IP string
	// Labels is the source workload's label map, parsed from
	// filter_state['agentio.workload.labels'] (or legacy sandbox.labels). Nil when pod identity is missing.
	Labels map[string]string
	// Token carries filter_state['agentio.sandbox.token']. Consumers must call Parse
	// before reading its fields. Copies of Peer share the same lazy result.
	Token *SandboxToken
}

// Valid reports whether filter_state carried a usable pod identity.
// The predicate mirrors the fail-open condition in the request handler: both
// the pod namespace AND the pod name must be non-empty.
func (p Peer) Valid() bool {
	return p.Pod.Namespace != "" && p.Pod.Name != ""
}

// SandboxToken holds the sandbox credential, decoded on first use. It must
// never be exposed to the evaluation Scope. Like Stream, it is request-scoped
// and accessed sequentially by the filter chain.
type SandboxToken struct {
	RequestID       string `json:"requestId"`
	AccessToken     string `json:"accessToken"`
	SandboxClientID string `json:"sandboxClientId"`

	raw     string
	invalid bool
}

// NewSandboxToken retains the wire value without decoding it.
func NewSandboxToken(raw string) *SandboxToken {
	if raw == "" {
		return nil
	}
	return &SandboxToken{raw: raw}
}

// Parse decodes base64 JSON (or raw JSON) once, including failed attempts.
// It only parses the envelope; it does not validate the access token.
// Pre-decoded tokens can also be supplied directly by callers.
func (t *SandboxToken) Parse(ctx context.Context) *SandboxToken {
	if t == nil || t.invalid {
		return nil
	}
	if t.raw == "" {
		return t
	}
	raw := t.raw
	t.raw = ""
	tokenJSON, decErr := base64.StdEncoding.DecodeString(raw)
	if decErr != nil {
		tokenJSON = []byte(raw)
	}
	if err := json.Unmarshal(tokenJSON, t); err != nil {
		t.invalid = true
		log.FromContext(ctx).V(logging.DEBUG).Info("failed to parse sandbox.token", "error", err)
		return nil
	}
	return t
}
