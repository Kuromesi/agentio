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

package model

import (
	"istio.io/istio/pkg/util/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type EgressRuleType string

const (
	EgressRuleTypeCIDR     EgressRuleType = "cidr"
	EgressRuleTypeService  EgressRuleType = "service"
	EgressRuleTypeFQDN     EgressRuleType = "fqdn"
	EgressRuleTypeWorkload EgressRuleType = "workload"
)

type EgressRuleAction string

const (
	EgressRuleActionAllow  EgressRuleAction = "allow"
	EgressRuleActionDeny   EgressRuleAction = "deny"
	EgressRuleActionReject EgressRuleAction = "reject"
)

type TrafficPolicyServiceRef struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// TrafficPolicyWorkloadRef selects pods by namespace and label selector.
// The IP addresses of all matching pods are collected into the IPSet.
type TrafficPolicyWorkloadRef struct {
	// Namespace of the target pods.
	Namespace string `json:"namespace"`
	// Selector is a label selector that matches the target pods.
	Selector map[string]string `json:"selector"`
}

type TrafficPolicyPeer struct {
	// +optional
	CIDR string `json:"cidr,omitempty"`
	// +optional
	FQDN string `json:"fqdn,omitempty"`
	// +optional
	Service *TrafficPolicyServiceRef `json:"service,omitempty"`
	// +optional
	Workload *TrafficPolicyWorkloadRef `json:"workload,omitempty"`
}

// TrafficPolicyPort restricts a rule to specific protocol/port combinations.
// If Protocol is empty, matches any protocol: with Port set, nft expands to
// TCP, UDP, and SCTP dport matches (ICMP has no ports and is not included);
// with Port nil, there is no L4 match (same as IP-only for that port entry).
// If Protocol is non-empty and Port is nil, matches all ports of that protocol.
type TrafficPolicyPort struct {
	// +optional
	// +kubebuilder:validation:Enum=TCP;UDP;ICMP;SCTP
	Protocol string `json:"protocol,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *int32 `json:"port,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	EndPort *int32 `json:"endPort,omitempty"`
}

type TrafficPolicyRule struct {
	// +kubebuilder:validation:Enum=allow;deny
	Action EgressRuleAction `json:"action"`
	// +optional
	From []TrafficPolicyPeer `json:"from,omitempty"`
	// +optional
	To []TrafficPolicyPeer `json:"to,omitempty"`
	// +optional
	Ports []TrafficPolicyPort `json:"ports,omitempty"`
}

type TrafficPolicyDirection struct {
	// +optional
	Rules []TrafficPolicyRule `json:"rules,omitempty"`
}

// TrafficPolicySpec defines bidirectional policy state on selected pods.
type TrafficPolicySpec struct {
	// +optional
	// +kubebuilder:default:=1000
	// +kubebuilder:validation:Minimum=0
	Priority int32 `json:"priority,omitempty"`

	Selector metav1.LabelSelector `json:"selector"`

	// +optional
	Ingress *TrafficPolicyDirection `json:"ingress,omitempty"`
	// +optional
	Egress *TrafficPolicyDirection `json:"egress,omitempty"`
}

// IPSetBinding records one SelectorIPSet referenced by a rule in this policy,
// along with the direction, action, rule index, and optional port restrictions.
type IPSetBinding struct {
	// Name of the SelectorIPSet object (e.g. "ipset-a1b2c3d4e5f6").
	IPSetName string `json:"ipsetName"`
	// Content hash (same as SelectorIPSet.Spec.IPSetID).
	IPSetID string `json:"ipsetID"`
	// "egress" or "ingress"
	Direction string `json:"direction"`
	// "allow" or "deny"
	Action EgressRuleAction `json:"action"`
	// Index of the rule within spec.egress.rules or spec.ingress.rules.
	RuleIndex int32 `json:"ruleIndex"`
	// +optional
	Ports []TrafficPolicyPort `json:"ports,omitempty"`
}

// TrafficPolicyStatus defines the observed state of TrafficPolicy.
type TrafficPolicyStatus struct {
	// IPSetBindings lists all SelectorIPSet objects referenced by this policy's rules.
	// +optional
	IPSetBindings []IPSetBinding `json:"ipsetBindings,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ep

// TrafficPolicy defines bidirectional traffic rules for selected pods.
type TrafficPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec TrafficPolicySpec `json:"spec,omitempty"`
	// +optional
	Status TrafficPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=gtp
//
// GlobalTrafficPolicy defines bidirectional traffic rules cluster-wide.
type GlobalTrafficPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec TrafficPolicySpec `json:"spec,omitempty"`
	// +optional
	Status TrafficPolicyStatus `json:"status,omitempty"`
}

func (p TrafficPolicy) ResourceName() string {
	return p.Namespace + "/" + p.Name
}

func (p GlobalTrafficPolicy) ResourceName() string {
	return p.Name
}

func ExtractHostnameFromTrafficPolicy(policy *TrafficPolicy) sets.String {
	return extractFromPolicy(&policy.Spec)
}

func ExtractHostnameFromGlobalTrafficPolicy(policy *GlobalTrafficPolicy) sets.String {
	return extractFromPolicy(&policy.Spec)
}

func extractFromPolicy(policy *TrafficPolicySpec) sets.Set[string] {
	hosts := sets.New[string]()
	if policy.Egress != nil {
		for _, rule := range policy.Egress.Rules {
			for _, to := range rule.To {
				hosts.Insert(to.FQDN)
			}
			for _, from := range rule.From {
				hosts.Insert(from.FQDN)
			}
		}
	}

	if policy.Ingress != nil {
		for _, rule := range policy.Ingress.Rules {
			for _, to := range rule.To {
				hosts.Insert(to.FQDN)
			}
			for _, from := range rule.From {
				hosts.Insert(from.FQDN)
			}
		}
	}

	return hosts
}
