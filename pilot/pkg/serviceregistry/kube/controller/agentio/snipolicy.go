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

package agentio

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	agentvalidation "istio.io/istio/pkg/config/validation/agent"
)

// wildcardAny is the SNI value that matches any non-empty SNI.
const wildcardAny = "*"

// wildcardPrefix is the only legal way for an SNI value to begin with '*'
// besides being exactly wildcardAny.
const wildcardPrefix = "*."

// normalizeSNI lowercases value and strips one trailing dot, then validates it
// against the accepted SNI forms:
//
//   - an exact DNS name, e.g. "example.com"
//   - a leading wildcard label, e.g. "*.example.com", which matches names with
//     at least one label before "example.com" and does NOT match the apex
//   - "*" alone, which matches any non-empty SNI
//
// Anything else - including glob or regex syntax, and a '*' that is not the
// complete leftmost label - is rejected.
func normalizeSNI(value string) (string, error) {
	normalized := strings.ToLower(value)
	// Strip exactly one trailing dot so "Example.COM." and "example.com" are the
	// same value. A bare "." normalizes to the empty string and is rejected below.
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" {
		return "", fmt.Errorf("sni value %q is empty", value)
	}
	// Only ONE trailing dot is stripped, so a residual trailing dot means the
	// input had several. ValidateDNS1123Labels deliberately tolerates a trailing
	// empty label ("istio.io." is a valid FQDN there), which would let
	// "example.com.." through as "example.com." - a value that is not idempotent
	// under normalization and would therefore never match a normalized SNI.
	if strings.HasSuffix(normalized, ".") {
		return "", fmt.Errorf("sni value %q invalid: more than one trailing dot", value)
	}

	if normalized == wildcardAny {
		return normalized, nil
	}

	// A '*' is legal only as the complete leftmost label. This restriction is
	// stricter than Istio's ValidateWildcardDomain, which delegates the first
	// label to labels.IsWildcardDNS1123Label and therefore also accepts partial
	// wildcards such as "*foo.example.com" and "*-foo.example.com". Those forms
	// are not part of the accepted SNI grammar, so enforce the position rule here
	// and delegate the DNS label syntax below, rather than forking the label
	// regexes.
	if strings.Contains(normalized, wildcardAny) {
		// State the rule directly: a legal wildcard value is exactly "*." followed
		// by a domain containing no further '*'. Both halves are asserted even
		// though ValidateWildcardDomain currently also rejects a stray '*' in the
		// non-leading labels via ValidateDNS1123Labels - relying on that would make
		// this function's contract depend on an implementation detail of a helper
		// that is free to loosen.
		rest, hadWildcardPrefix := strings.CutPrefix(normalized, wildcardPrefix)
		if !hadWildcardPrefix || strings.Contains(rest, wildcardAny) {
			return "", fmt.Errorf("sni value %q invalid: %q is only allowed as the complete leftmost label", value, wildcardAny)
		}
		if err := agentvalidation.ValidateWildcardDomain(normalized); err != nil {
			return "", fmt.Errorf("sni value %q invalid: %v", value, err)
		}
		return normalized, nil
	}

	if err := agentvalidation.ValidateFQDN(normalized); err != nil {
		return "", fmt.Errorf("sni value %q invalid: %v", value, err)
	}
	return normalized, nil
}

// normalizeSniTrafficPolicy returns a normalized deep copy of p, or an error if
// p is not valid. The input is never mutated.
//
// Each rule must specify an action other than SNI_ACTION_UNSPECIFIED and a match
// with at least one SNI value. SNI values are normalized via NormalizeSNI and
// deduplicated within a match, preserving first-occurrence order.
func normalizeSniTrafficPolicy(p *extensions.SniTrafficPolicy) (*extensions.SniTrafficPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("sni traffic policy is nil")
	}
	out := proto.Clone(p).(*extensions.SniTrafficPolicy)
	for i, rule := range out.GetRules() {
		if rule.GetAction() == extensions.SniAction_SNI_ACTION_UNSPECIFIED {
			return nil, fmt.Errorf("rules[%d]: action is unspecified", i)
		}
		if rule.GetMatch() == nil {
			return nil, fmt.Errorf("rules[%d]: match is required", i)
		}
		if len(rule.GetMatch().GetSni()) == 0 {
			return nil, fmt.Errorf("rules[%d]: match.sni must not be empty", i)
		}
		seen := make(map[string]struct{}, len(rule.GetMatch().GetSni()))
		normalized := make([]string, 0, len(rule.GetMatch().GetSni()))
		for j, value := range rule.GetMatch().GetSni() {
			n, err := normalizeSNI(value)
			if err != nil {
				return nil, fmt.Errorf("rules[%d].match.sni[%d]: %v", i, j, err)
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			normalized = append(normalized, n)
		}
		rule.Match.Sni = normalized
	}
	return out, nil
}

// PolicyRef is a referenced bindable policy together with the source fields
// needed to reproduce the policy API's deterministic ordering contract.
type PolicyRef struct {
	ResourceName    string
	Priority        int32
	CreationTime    time.Time
	SourceName      string
	SourceNamespace string
}

// sortPolicyRefs returns resource names in the control-plane ordering
// contract: descending internal priority, then ascending source creation time,
// name, and namespace. SecurityProfile priorities are negated during conversion,
// so descending internal priority implements its lower-values-first API rule.
// ResourceName is the final tie-breaker, making the ordering total even for
// future policy sources whose source identities overlap.
func sortPolicyRefs(refs []PolicyRef) []string {
	sorted := make([]PolicyRef, len(refs))
	copy(sorted, refs)
	// The comparator ends with ResourceName, so it defines a total order and
	// stability cannot affect the output. Avoid SliceStable here: its merge
	// rotations copy PolicyRef values heavily and become a dominant cost when a
	// workload is selected by tens of thousands of policies.
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		if !sorted[i].CreationTime.Equal(sorted[j].CreationTime) {
			return sorted[i].CreationTime.Before(sorted[j].CreationTime)
		}
		if sorted[i].SourceName != sorted[j].SourceName {
			return sorted[i].SourceName < sorted[j].SourceName
		}
		if sorted[i].SourceNamespace != sorted[j].SourceNamespace {
			return sorted[i].SourceNamespace < sorted[j].SourceNamespace
		}
		return sorted[i].ResourceName < sorted[j].ResourceName
	})
	names := make([]string, 0, len(sorted))
	for _, ref := range sorted {
		names = append(names, ref.ResourceName)
	}
	return names
}
