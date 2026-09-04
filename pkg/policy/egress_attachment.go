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

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/util/sets"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// BindableEgressPolicy keeps the typed payload separate from its payload-free
// attachment projection.
type BindableEgressPolicy struct {
	Name       string
	Attachment PolicyAttachment
	Policy     *extensionsv1.EgressPolicy
	GatewayKey string
}

func (p BindableEgressPolicy) ResourceName() string { return p.Name }

func (p BindableEgressPolicy) Equals(other BindableEgressPolicy) bool {
	return p.Name == other.Name &&
		p.Attachment.Equals(other.Attachment) &&
		p.GatewayKey == other.GatewayKey &&
		proto.Equal(p.Policy, other.Policy)
}

// BindableEgressPolicies adapts the ordered ConfigMap policy list into typed
// payload values and the common attachment representation. The list index is
// retained as both priority and source order, preserving first-match behavior.
func BindableEgressPolicies(
	rootNamespace string,
	compiled *extensionsv1.EgressPolicies,
) ([]BindableEgressPolicy, error) {
	if compiled == nil {
		return nil, nil
	}
	result := make([]BindableEgressPolicy, 0, len(compiled.GetEgressPolicies()))
	for index, source := range compiled.GetEgressPolicies() {
		if source == nil {
			return nil, fmt.Errorf("egress policy %d is nil", index)
		}
		name := fmt.Sprintf("agentio-config/egress/%06d", index)
		target := AttachmentTarget{Namespaces: append([]string(nil), source.GetNamespaces()...)}
		if len(target.Namespaces) == 0 {
			target.Global = true
		}
		attachment, err := NewPolicyAttachment(PolicyAttachment{
			Kind:            PolicyKindEgressPolicy,
			Name:            name,
			Target:          target,
			Priority:        int32(index),
			SourceOrder:     int32(index),
			SourceName:      "agentio-config",
			SourceNamespace: rootNamespace,
		})
		if err != nil {
			return nil, fmt.Errorf("egress policy %d attachment: %w", index, err)
		}
		gatewayKey := ""
		if source.GetPolicy() == extensionsv1.EgressPolicyAction_GATEWAY {
			var valid bool
			gatewayKey, valid = model.GatewayKeyFromService(source.GetGateway().GetService())
			if !valid {
				return nil, fmt.Errorf("egress policy %d has invalid gateway service %q",
					index, source.GetGateway().GetService())
			}
		}
		result = append(result, BindableEgressPolicy{
			Name: name, Attachment: attachment,
			Policy: proto.Clone(source).(*extensionsv1.EgressPolicy), GatewayKey: gatewayKey,
		})
	}
	return result, nil
}

func NewEgressPolicyAttachmentsCollection(
	policies krt.Collection[BindableEgressPolicy],
	options krt.OptionsBuilder,
) krt.Collection[PolicyAttachment] {
	return krt.NewCollection(policies,
		func(_ krt.HandlerContext, policy BindableEgressPolicy) *PolicyAttachment {
			attachment := policy.Attachment
			return &attachment
		}, options.WithName("egress-policy-attachments")...)
}

// SelectEgressPolicies returns the policy payloads and gateway keys named by one Sandbox binding, in binding order.
func SelectEgressPolicies(
	names []string,
	policies []BindableEgressPolicy,
) (*extensionsv1.EgressPolicies, []string, error) {
	if len(names) == 0 {
		return nil, nil, nil
	}
	byName := make(map[string]BindableEgressPolicy, len(policies))
	for _, current := range policies {
		if _, found := byName[current.Name]; found {
			return nil, nil, fmt.Errorf("duplicate egress policy payload %q", current.Name)
		}
		byName[current.Name] = current
	}
	selected := &extensionsv1.EgressPolicies{
		EgressPolicies: make([]*extensionsv1.EgressPolicy, 0, len(names)),
	}
	gatewaySet := sets.New[string]()
	for _, name := range names {
		current, found := byName[name]
		if !found {
			return nil, nil, fmt.Errorf("egress policy payload %q is missing", name)
		}
		selected.EgressPolicies = append(
			selected.EgressPolicies,
			proto.Clone(current.Policy).(*extensionsv1.EgressPolicy),
		)
		if current.GatewayKey != "" {
			gatewaySet.Insert(current.GatewayKey)
		}
	}
	gatewayKeys := make([]string, 0, len(gatewaySet))
	for key := range gatewaySet {
		gatewayKeys = append(gatewayKeys, key)
	}
	sort.Strings(gatewayKeys)
	return selected, gatewayKeys, nil
}
