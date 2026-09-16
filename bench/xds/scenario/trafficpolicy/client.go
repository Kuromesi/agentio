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

package trafficpolicy

import (
	"encoding/json"
	"errors"
	"fmt"

	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	security "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario"
)

// PolicyType is the type URL of a shared TrafficPolicy resource.
const PolicyType = "type.googleapis.com/agentio.security.TrafficPolicy"

// SandboxType is the type URL of a Sandbox resource.
const SandboxType = "type.googleapis.com/agentio.sandbox.Sandbox"

// ClientOptions identifies the policy and Sandbox expected by a client.
type ClientOptions struct {
	PolicyName string `json:"policy_name"`
	SandboxID  string `json:"sandbox_id"`
}

// Round describes the policy payload expected after a managed update.
type Round struct {
	Marker    uint32 `json:"marker"`
	Action    int32  `json:"action"`
	RuleCount int    `json:"rule_count"`
	Ports     int    `json:"ports"`
}

// Validate checks the marker, action, and payload size bounds.
func (r Round) Validate() error {
	if r.Marker < 1 || r.Marker > 65535 || r.Action < 0 || r.Action > 1 || r.RuleCount < 2 || r.RuleCount > 50001 ||
		r.Ports < 1 ||
		r.Ports > 50000/(r.RuleCount-1) {
		return errors.New("invalid TrafficPolicy round")
	}
	return nil
}

// New creates clients that verify Sandbox bindings and TrafficPolicy updates.
func New(raw json.RawMessage) (scenario.ClientFactory, error) {
	var cfg ClientOptions
	if err := scenario.Decode(raw, &cfg); err != nil {
		return scenario.ClientFactory{}, err
	}
	if cfg.PolicyName == "" || cfg.SandboxID == "" {
		return scenario.ClientFactory{}, errors.New("policy_name and sandbox_id are required")
	}
	return scenario.ClientFactory{New: func() scenario.Client { return &client{cfg: cfg} },
		PrepareRound: func(raw json.RawMessage) (any, error) {
			var r Round
			if err := scenario.Decode(raw, &r); err != nil {
				return nil, err
			}
			return r, r.Validate()
		}}, nil
}

type client struct {
	cfg         ClientOptions
	seenPolicy  bool
	seenSandbox bool
}

func (c *client) Subscriptions() []scenario.Subscription {
	var out []scenario.Subscription
	for _, typ := range []string{"type.googleapis.com/istio.workload.Address", "type.googleapis.com/istio.security.Authorization", PolicyType, SandboxType} {
		out = append(out, scenario.Subscription{TypeURL: typ})
	}
	return out
}
func (c *client) Observe(response *ads.DeltaDiscoveryResponse, expected any) (scenario.Observation, error) {
	result := scenario.Observation{}
	switch response.TypeUrl {
	case PolicyType:
		for _, r := range response.Resources {
			if r.Name != c.cfg.PolicyName {
				continue
			}
			var p security.TrafficPolicy
			if err := r.Resource.UnmarshalTo(&p); err != nil {
				return result, err
			}
			rules := p.GetEgress().GetRules()
			if len(rules) < 2 || len(rules[0].GetMatch().GetPorts()) == 0 || r.Version == "" {
				return result, errors.New("malformed/unversioned policy")
			}
			c.seenPolicy = true
			if expected != nil {
				round, ok := expected.(Round)
				if !ok {
					return result, errors.New("unexpected TrafficPolicy expectation")
				}
				if rules[0].GetMatch().GetPorts()[0].GetPort() == round.Marker {
					if err := checkPolicy(&p, round); err != nil {
						return result, err
					}
					result.Sample = &loadapi.Sample{Version: r.Version, Bytes: len(r.Resource.Value)}
				}
			}
		}
	case SandboxType:
		for _, r := range response.Resources {
			var s sandbox.Sandbox
			if err := r.Resource.UnmarshalTo(&s); err != nil {
				return result, err
			}
			if s.Uid == c.cfg.SandboxID {
				for _, name := range s.PolicyRefs[PolicyType].GetResourceNames() {
					if name == c.cfg.PolicyName {
						c.seenSandbox = true
					}
				}
			}
		}
	}
	result.Ready = c.seenPolicy && c.seenSandbox
	return result, nil
}

func checkPolicy(p *security.TrafficPolicy, r Round) error {
	rules := p.GetEgress().GetRules()
	if len(rules) != r.RuleCount || int32(rules[len(rules)-1].GetAction()) != r.Action {
		return errors.New("rule count or final action mismatch")
	}
	for i, rule := range rules[:len(rules)-1] {
		ports := rule.GetMatch().GetPorts()
		if rule.GetAction() != security.TrafficPolicy_DENY || len(ports) != r.Ports {
			return fmt.Errorf("rule %d action/port count mismatch", i)
		}
		for j, port := range ports {
			expected := uint32(12000 + i*r.Ports + j)
			if i == 0 && j == 0 {
				expected = r.Marker
			}
			if port.GetProtocol() != security.TrafficPolicy_UDP || port.GetPort() != expected {
				return fmt.Errorf("rule %d port %d mismatch", i, j)
			}
		}
	}
	return nil
}
