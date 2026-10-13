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

package policy

import (
	"fmt"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

// CompileSNIRules projects HTTPS-capable security matches into SNI termination rules.
// Sandbox-owned rules and shared SecurityProfiles use the same projection.
func CompileSNIRules(rules []agentsv1alpha1.SecurityRule) (*extensionsv1.SniTrafficPolicy, error) {
	hosts, err := sniHosts(rules)
	if err != nil || len(hosts) == 0 {
		return nil, err
	}
	return &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
		Match:  &extensionsv1.SniMatch{Sni: hosts},
		Action: extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION,
	}}}, nil
}

func sniHosts(rules []agentsv1alpha1.SecurityRule) ([]string, error) {
	seen := sets.New[string]()
	result := make([]string, 0)
	for ruleIndex, rule := range rules {
		for matchIndex, match := range rule.Match {
			if !mayMatchHTTPS(match.Schemes) {
				continue
			}
			for domainIndex, domain := range match.Domains {
				normalized, err := normalizeSNI(domain)
				if err != nil {
					return nil, fmt.Errorf("rules[%d].match[%d].domains[%d]: %w",
						ruleIndex, matchIndex, domainIndex, err)
				}
				if seen.Contains(normalized) {
					continue
				}
				seen.Insert(normalized)
				result = append(result, normalized)
			}
		}
	}
	return result, nil
}

func mayMatchHTTPS(schemes []string) bool {
	if len(schemes) == 0 {
		return true
	}
	for _, scheme := range schemes {
		if strings.EqualFold(scheme, "https") {
			return true
		}
	}
	return false
}

func normalizeSNI(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSuffix(value, "."))
	if normalized == "" || strings.HasSuffix(normalized, ".") {
		return "", fmt.Errorf("invalid SNI value %q", value)
	}
	if normalized == "*" {
		return normalized, nil
	}
	if strings.Contains(normalized, "*") {
		rest, ok := strings.CutPrefix(normalized, "*.")
		if !ok || strings.Contains(rest, "*") || len(validation.IsDNS1123Subdomain(rest)) > 0 {
			return "", fmt.Errorf("wildcard must be the complete leftmost label in %q", value)
		}
		return normalized, nil
	}
	if problems := validation.IsDNS1123Subdomain(normalized); len(problems) > 0 {
		return "", fmt.Errorf("invalid DNS name %q: %s", value, strings.Join(problems, "; "))
	}
	return normalized, nil
}
