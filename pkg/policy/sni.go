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
	"sort"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// BindableSNIPolicy is the complete SNI policy published over xDS together with
// the immutable metadata needed to project its workload attachment.
type BindableSNIPolicy struct {
	Name         string
	Namespace    string
	SandboxUID   string
	Global       bool
	Priority     int32
	CreationTime time.Time
	Selector     metav1.LabelSelector
	Policy       *extensionsv1.SniTrafficPolicy

	// selector is the immutable compiled form used by PolicyAttachment. Selector
	// is its canonical source of truth and is the only form used for equality.
	selector labels.Selector
}

func (p BindableSNIPolicy) ResourceName() string { return p.Name }

func (p BindableSNIPolicy) Equals(other BindableSNIPolicy) bool {
	return p.Name == other.Name &&
		p.Namespace == other.Namespace &&
		p.SandboxUID == other.SandboxUID &&
		p.Global == other.Global &&
		p.Priority == other.Priority &&
		p.CreationTime.Equal(other.CreationTime) &&
		apiequality.Semantic.DeepEqual(p.Selector, other.Selector) &&
		proto.Equal(p.Policy, other.Policy)
}

func (p BindableSNIPolicy) SourceResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Name
}

// CompileSNIProfile compiles one profile; profiles with no HTTPS-capable hosts return nil, nil.
func CompileSNIProfile(profile model.SecurityProfile) (*BindableSNIPolicy, error) {
	hosts, err := sniHosts(profile)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	priority := agentsv1alpha1.DefaultSecurityProfilePriority
	if profile.Spec.Priority != nil {
		priority = *profile.Spec.Priority
	}
	if priority < 0 {
		return nil, fmt.Errorf("security profile %s priority %d is negative", profile.ResourceName(), priority)
	}
	sandboxUID, err := policySandboxUID(profile.SandboxUID, profile.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("security profile %s: %w", profile.ResourceName(), err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&profile.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("security profile %s selector: %w", profile.ResourceName(), err)
	}
	resourceName := profile.Name
	if !profile.Global {
		resourceName = profile.Namespace + "/" + profile.Name
	}
	return &BindableSNIPolicy{
		Name:         resourceName,
		Namespace:    profile.Namespace,
		SandboxUID:   sandboxUID,
		Global:       profile.Global,
		Priority:     priority,
		CreationTime: profile.CreationTime,
		Selector:     *profile.Spec.Selector.DeepCopy(),
		selector:     selector,
		Policy: &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
			Match:  &extensionsv1.SniMatch{Sni: hosts},
			Action: extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION,
		}}},
	}, nil
}

// CompileSNIProfiles compiles a whole set, ordered deterministically.
func CompileSNIProfiles(profiles []model.SecurityProfile) ([]BindableSNIPolicy, error) {
	result := make([]BindableSNIPolicy, 0, len(profiles))
	for _, profile := range profiles {
		compiled, err := CompileSNIProfile(profile)
		if err != nil {
			return nil, err
		}
		if compiled == nil {
			continue
		}
		result = append(result, *compiled)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func sniHosts(profile model.SecurityProfile) ([]string, error) {
	seen := sets.New[string]()
	result := make([]string, 0)
	for ruleIndex, rule := range profile.Spec.Rules {
		for matchIndex, match := range rule.Match {
			if !mayMatchHTTPS(match.Schemes) {
				continue
			}
			for domainIndex, domain := range match.Domains {
				normalized, err := normalizeSNI(domain)
				if err != nil {
					return nil, fmt.Errorf("security profile %s rules[%d].match[%d].domains[%d]: %w",
						profile.ResourceName(), ruleIndex, matchIndex, domainIndex, err)
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
