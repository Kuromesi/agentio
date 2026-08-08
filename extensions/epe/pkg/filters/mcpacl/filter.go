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

// Package mcpacl enforces MCP tool ACLs. It cannot tell whether a request
// is a governed tools/call without the body — and enforcement must not be
// skippable via the client-controlled version header — so it always asks
// for the body and decides in the body phase.
package mcpacl

import (
	"context"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for attribution.
const FilterName = "mcpacl"

// actionAllow is the only value that admits a governed call. Every other
// value — actionDeny, a differently-cased or misspelled verb, an un-defaulted
// empty string — denies. Spelling the permissive value exactly, rather than the
// restrictive one, is what keeps an unrecognized action from silently disabling
// the rule it was written for.
const (
	actionAllow = "allow"
	actionDeny  = "deny"
)

// defaultDenyStatus is used when the policy does not configure a deny
// response status.
const defaultDenyStatus = 403

// Config is the filter's decoded form of an mcpacl policy payload.
type Config struct {
	DefaultAction            string
	UnsupportedVersionAction string
	// DenyStatus 0 means the default 403.
	DenyStatus int32
	DenyBody   string
	Rules      []RuleEntry
}

// RuleEntry is one policy rule.
type RuleEntry struct {
	Method    string
	ToolNames []string
	Action    string
}

// evaluate walks the policy rules for a decision; unmatched falls back to
// DefaultAction. The returned value is only ever honoured as an allow when it
// is exactly actionAllow — see the call site.
func evaluate(cfg Config, method, toolName string) string {
	for _, rule := range cfg.Rules {
		if rule.Method != method {
			continue
		}
		if len(rule.ToolNames) == 0 {
			return rule.Action
		}
		if toolName == "" {
			continue
		}
		if contains(rule.ToolNames, toolName) {
			return rule.Action
		}
	}
	return cfg.DefaultAction
}

func contains(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}

func denyReply(cfg Config) filter.Reply {
	status := int(cfg.DenyStatus)
	if status == 0 {
		status = defaultDenyStatus
	}
	var body []byte
	if cfg.DenyBody != "" {
		body = []byte(cfg.DenyBody)
	}
	return filter.Reply{Status: status, Body: body}
}

// Filter evaluates one rule's MCP tool policy.
type Filter struct {
	filter.PassThrough
	rule filter.RuleConfig[Config]
}

func New(rule filter.RuleConfig[Config]) filter.Filter { return &Filter{rule: rule} }

// OnRequestHeaders always asks for the body: the governed method is only
// knowable from the JSON-RPC payload.
func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

// OnRequestBody applies the rule's policy to the single JSON-RPC message
// carried in the body; only an exact allow admits a governed call.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	read := readBody(st.Request.Headers, body.Bytes)

	// A body the ACL cannot read as one JSON-RPC message hides the tool name
	// while staying actionable by a lenient upstream parser, so it is denied
	// outright rather than routed through defaultAction. Checked before the
	// version header so it cannot be bypassed through it.
	if read.status == statusUnreadable {
		cfg := f.rule
		log.FromContext(ctx).Info("MCP request body is not a readable single JSON-RPC message, denying",
			"rule", cfg.ID.Name,
			"pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg.Cfg)), nil
	}

	// Only tool invocations are governed; a body with no message at all, and
	// any other method (lifecycle, tools/list, resources/*, prompts/*,
	// tasks/*, ...) passes.
	if read.status == statusAbsent || !governedMethods[read.method] {
		return filter.Continue(), nil
	}
	method, toolName := read.method, read.tool

	version := st.Request.Headers[mcpProtocolVersionHeader]
	rc := f.rule
	cfg := rc.Cfg
	// A tool call MUST come from a supported protocol version unless
	// the policy opts out via unsupportedVersionAction=passthrough.
	if !supportedMCPVersions[version] {
		if cfg.UnsupportedVersionAction == "passthrough" {
			log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, passing through per policy",
				"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
			return filter.Continue(), nil
		}
		log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, denying",
			"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}

	// A governed call whose tool name is absent or not a string cannot be
	// attributed to a tool-scoped rule. Falling through to defaultAction would
	// admit it under a blacklist policy, so an unattributable call is denied
	// for the same reason an unreadable body is.
	if !read.hasTool {
		log.FromContext(ctx).Info("MCP tool call without a readable tool name, denying",
			"rule", rc.ID.Name, "method", method, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}

	if decision := evaluate(cfg, method, toolName); decision != actionAllow {
		log.FromContext(ctx).Info("MCP tool denied by policy",
			"rule", rc.ID.Name, "method", method, "toolName", toolName,
			"decision", decision, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}
	return filter.Continue(), nil
}

// Descriptor declares mcpacl's complete-body contract.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Body:    filter.BodyComplete,
		OnError: filter.FailClosed,
		New:     New,
	}
}
