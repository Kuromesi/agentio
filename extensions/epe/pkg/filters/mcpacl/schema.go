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
package mcpacl

import (
	"encoding/json"
	"strings"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// spec is the wire form of an mcpacl payload; tags mirror the CRD's
// MCPToolPolicySpec. Config keeps the deny response
// flattened, so spec is a distinct type rather than Config with tags.
type spec struct {
	DefaultAction            string        `json:"defaultAction,omitempty"`
	UnsupportedVersionAction string        `json:"unsupportedVersionAction,omitempty"`
	DenyResponse             *denyResponse `json:"denyResponse,omitempty"`
	Rules                    []ruleSpec    `json:"rules,omitempty"`
}

type denyResponse struct {
	StatusCode int32  `json:"statusCode,omitempty"`
	Body       string `json:"body,omitempty"`
}

type ruleSpec struct {
	Method    string   `json:"method,omitempty"`
	ToolNames []string `json:"toolNames,omitempty"`
	Action    string   `json:"action,omitempty"`
}

// parse builds a Config from one payload document. Action vocabularies are
// normalized here and failed closed at evaluation, so the invariant holds for
// every payload source, not just the API server's defaulting.
func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	cfg := Config{
		DefaultAction:            s.DefaultAction,
		UnsupportedVersionAction: s.UnsupportedVersionAction,
	}
	if s.DenyResponse != nil {
		cfg.DenyStatus = s.DenyResponse.StatusCode
		cfg.DenyBody = s.DenyResponse.Body
	}
	for _, r := range s.Rules {
		cfg.Rules = append(cfg.Rules, RuleEntry{
			Method:    r.Method,
			ToolNames: r.ToolNames,
			Action:    r.Action,
		})
	}
	return normalizeActions(cfg), nil
}

// normalizeActions lower-cases and trims every action vocabulary in cfg.
//
// The CRD spells these enums in lower case, so a differently-cased value can
// only come from a payload that skipped API-server validation — and there an
// operator who wrote "Allow" meant allow. Normalizing honours that, while
// evaluation still fails closed on a value that is not in the vocabulary at
// all: casing is a spelling mistake, an unknown verb is an unknown intent.
func normalizeActions(cfg Config) Config {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	cfg.DefaultAction = norm(cfg.DefaultAction)
	cfg.UnsupportedVersionAction = norm(cfg.UnsupportedVersionAction)
	for i := range cfg.Rules {
		cfg.Rules[i].Action = norm(cfg.Rules[i].Action)
	}
	return cfg
}

// Definition returns the typed MCP ACL definition.
func Definition() filter.Definition { return filter.Define(Descriptor(), parse) }
