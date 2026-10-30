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

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// CallerContext carries the request's Workload/Sandbox identities and its credential.
// Credentials are separate from Subject and never expression-visible.
type CallerContext struct {
	Subject subject.Subject
	// Token is parsed lazily; copies of CallerContext share the same result.
	Token *SandboxToken
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
