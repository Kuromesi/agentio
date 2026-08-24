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
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
	pm "istio.io/istio/pkg/model"
)

// BindablePolicy is the common control-plane representation for an Agentio
// policy that is both published over xDS and bound to selected workloads.
// Policy-specific Kubernetes APIs only need to convert into this type.
type BindablePolicy struct {
	// Name is the complete xDS resource name. ResourceName() adds TypeURL only
	// for uniqueness inside the shared krt collection.
	Name       string
	TypeURL    string
	ConfigKind kind.Kind
	Namespace  string
	Priority   int32
	// CreationTime, SourceName, and SourceNamespace preserve the ordering
	// metadata defined by the source policy API. They are not published in the
	// policy resource; Workload policy references use them only to order names.
	CreationTime    time.Time
	SourceName      string
	SourceNamespace string
	// An empty Namespace applies to every namespace. An empty selector matches
	// every workload in the policy's namespace scope.
	Selector metav1.LabelSelector
	Resource proto.Message

	// selector is the immutable compiled form used on the hot workload-reference
	// path. It is intentionally excluded from equality: Selector is its source of
	// truth and equivalent selectors must not produce spurious krt updates.
	selector klabels.Selector
}

var bindablePolicyConfigKinds = map[string]kind.Kind{
	pm.SniTrafficPolicyType: kind.SniTrafficPolicy,
}

// BindablePolicyConfigKind returns the control-plane config kind carried by a
// bindable policy TypeURL. New bindable policy implementations register here
// so shared reference projection remains policy-type agnostic.
func BindablePolicyConfigKind(typeURL string) (kind.Kind, bool) {
	configKind, found := bindablePolicyConfigKinds[typeURL]
	return configKind, found
}

func (p BindablePolicy) ResourceName() string {
	return p.TypeURL + "|" + p.Name
}

func (p BindablePolicy) XDSResourceName() string {
	return p.Name
}

func (p BindablePolicy) ConfigKey() model.ConfigKey {
	return model.ConfigKey{Kind: p.ConfigKind, Name: p.Name}
}

func (p BindablePolicy) Equals(other BindablePolicy) bool {
	return p.Name == other.Name &&
		p.TypeURL == other.TypeURL &&
		p.ConfigKind == other.ConfigKind &&
		p.Namespace == other.Namespace &&
		p.Priority == other.Priority &&
		p.CreationTime.Equal(other.CreationTime) &&
		p.SourceName == other.SourceName &&
		p.SourceNamespace == other.SourceNamespace &&
		apiequality.Semantic.DeepEqual(p.Selector, other.Selector) &&
		proto.Equal(p.Resource, other.Resource)
}

// Selects reports whether the policy applies to a workload with the given
// namespace and labels. An empty policy namespace means all namespaces; an
// empty selector matches every workload in that namespace scope.
func (p BindablePolicy) Selects(namespace string, workloadLabels map[string]string) bool {
	return policySelectsWorkload(p.Namespace, p.Selector, p.selector, namespace, workloadLabels)
}

// BindablePolicy is used directly as a krt collection value type, which
// requires ResourceName() for keying and Equals() for equality suppression.
var (
	_ krt.ResourceNamer           = BindablePolicy{}
	_ krt.Equaler[BindablePolicy] = BindablePolicy{}
)

func matchMayApplyToHTTPS(schemes []string) bool {
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

func bindablePolicyFromSecurityProfile(policy *agentsv1alpha1.SecurityProfile) (*BindablePolicy, error) {
	if policy == nil {
		return nil, fmt.Errorf("SecurityProfile is nil")
	}
	return bindablePolicyFromSecurityProfileSpec(
		"SecurityProfile", policy.ObjectMeta, &policy.Spec,
	)
}

func bindablePolicyFromGlobalSecurityProfile(policy *agentsv1alpha1.GlobalSecurityProfile) (*BindablePolicy, error) {
	if policy == nil {
		return nil, fmt.Errorf("GlobalSecurityProfile is nil")
	}
	return bindablePolicyFromSecurityProfileSpec("GlobalSecurityProfile", policy.ObjectMeta, &policy.Spec)
}

func bindablePolicyFromSecurityProfileSpec(
	resourceKind string,
	metadata metav1.ObjectMeta,
	spec *agentsv1alpha1.SecurityProfileSpec,
) (*BindablePolicy, error) {
	resourceName := metadata.Name
	if metadata.Namespace != "" {
		resourceName = metadata.Namespace + "/" + metadata.Name
	}
	selector, err := metav1.LabelSelectorAsSelector(&spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("%s %s has invalid selector: %w", resourceKind, resourceName, err)
	}

	priority := ptr.Deref(spec.Priority, agentsv1alpha1.DefaultSecurityProfilePriority)
	if priority < 0 {
		return nil, fmt.Errorf("%s %s has negative priority %d", resourceKind, resourceName, priority)
	}

	seen := make(map[string]struct{})
	hosts := make([]string, 0)
	for i, rule := range spec.Rules {
		for j, match := range rule.Match {
			if !matchMayApplyToHTTPS(match.Schemes) {
				continue
			}
			for k, domain := range match.Domains {
				normalized, err := normalizeSNI(domain)
				if err != nil {
					return nil, fmt.Errorf("%s %s rules[%d].match[%d].domains[%d]: %w",
						resourceKind, resourceName, i, j, k, err)
				}
				if _, found := seen[normalized]; found {
					continue
				}
				seen[normalized] = struct{}{}
				hosts = append(hosts, normalized)
			}
		}
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	resource, err := normalizeSniTrafficPolicy(&extensions.SniTrafficPolicy{
		Rules: []*extensions.SniRule{{
			Match:  &extensions.SniMatch{Sni: hosts},
			Action: extensions.SniAction_SNI_ACTION_TLS_TERMINATION,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("%s %s produced invalid SNI policy: %w", resourceKind, resourceName, err)
	}

	return &BindablePolicy{
		Name:       resourceName,
		TypeURL:    pm.SniTrafficPolicyType,
		ConfigKind: kind.SniTrafficPolicy,
		Namespace:  metadata.Namespace,
		// SecurityProfile evaluates lower numeric priorities first. BindablePolicy
		// uses a generic higher-first ordering key, so negate the API value once at
		// the source boundary.
		Priority:        -priority,
		CreationTime:    metadata.CreationTimestamp.Time,
		SourceName:      metadata.Name,
		SourceNamespace: metadata.Namespace,
		Selector:        *spec.Selector.DeepCopy(),
		Resource:        resource,
		selector:        selector,
	}, nil
}

func newBindablePoliciesCollection(
	profiles krt.Collection[*agentsv1alpha1.SecurityProfile],
	globalProfiles krt.Collection[*agentsv1alpha1.GlobalSecurityProfile],
	opts krt.OptionsBuilder,
) krt.Collection[BindablePolicy] {
	securityProfilePolicies := krt.NewManyCollection(profiles, func(_ krt.HandlerContext, profile *agentsv1alpha1.SecurityProfile) []BindablePolicy {
		policy, err := bindablePolicyFromSecurityProfile(profile)
		if err != nil {
			log.Warnf("dropping invalid SecurityProfile policy: %v", err)
			return nil
		}
		if policy == nil {
			return nil
		}
		return []BindablePolicy{*policy}
	}, opts.WithName("SecurityProfileBindablePolicies")...)
	globalSecurityProfilePolicies := krt.NewManyCollection(globalProfiles,
		func(_ krt.HandlerContext, profile *agentsv1alpha1.GlobalSecurityProfile) []BindablePolicy {
			policy, err := bindablePolicyFromGlobalSecurityProfile(profile)
			if err != nil {
				log.Warnf("dropping invalid GlobalSecurityProfile policy: %v", err)
				return nil
			}
			if policy == nil {
				return nil
			}
			return []BindablePolicy{*policy}
		}, opts.WithName("GlobalSecurityProfileBindablePolicies")...)

	// Debounce once here, before the xDS policy resources and the workload
	// attachments split into separate branches. Debouncing further downstream
	// (on PolicyAttachments) coalesces reference recomputes but leaves the policy
	// xDS branch to fan each event out into its own push.
	policyOpts := append(opts.WithName("BindablePolicies"), krt.WithDebounce(
		features.KrtEventDistributeDebounce,
		features.KrtEventDistributeDebounceMax,
	))
	return krt.JoinCollection([]krt.Collection[BindablePolicy]{
		securityProfilePolicies,
		globalSecurityProfilePolicies,
	}, policyOpts...)
}

// initBindablePolicies wires Agentio bindable policies. It is a no-op unless
// the current SNI policy feature is enabled.
func (c *Controller) initBindablePolicies(opts krt.OptionsBuilder) {
	if !features.EnableSniTrafficPolicy {
		// Inert: build nothing at all, so the getters keep returning nil.
		return
	}

	c.bindablePolicies = newBindablePoliciesCollection(c.securityProfiles, c.globalSecurityProfiles, opts)
	c.policyAttachments = newPolicyAttachmentsCollection(c.bindablePolicies, opts)
}
