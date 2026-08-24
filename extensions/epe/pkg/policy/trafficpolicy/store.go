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
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// Decision is the CONNECT-time result. Enforced distinguishes an explicit
// policy allow from compatibility passthrough when no policy selects the pod.
type Decision struct {
	Enforced bool
	Allowed  bool
	Policy   string
	Rule     int
}

type snapshot struct {
	policies []Policy
}

// Store is a copy-on-write policy store. Reads are lock-free; informer event
// batches rebuild and atomically publish the ordered policy list.
type Store struct {
	snapshot atomic.Pointer[snapshot]
	mu       sync.Mutex
	policies map[string]Policy
}

func NewStore() *Store {
	s := &Store{policies: make(map[string]Policy)}
	s.snapshot.Store(&snapshot{})
	return s
}

// RegisterCollection materializes and tails a compiled policy collection.
func (s *Store) RegisterCollection(policies krt.Collection[Policy]) krt.HandlerRegistration {
	return policies.RegisterBatch(s.applyBatch, true)
}

func (s *Store) applyBatch(events []krt.Event[Policy]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, event := range events {
		latest := event.Latest()
		key := latest.ResourceName()
		if event.Event == controllers.EventDelete {
			delete(s.policies, key)
			continue
		}
		if event.New.CompileError != "" {
			ctrllog.Log.WithName("traffic-policy").Error(nil,
				"traffic policy version rejected; retaining last-known-good version",
				"policy", event.New.displayName(), "err", event.New.CompileError)
			continue
		}
		s.policies[key] = *event.New
	}
	s.publishLocked()
}

func (s *Store) publishLocked() {
	policies := make([]Policy, 0, len(s.policies))
	for _, policy := range s.policies {
		policies = append(policies, policy)
	}
	sortPolicies(policies)
	s.snapshot.Store(&snapshot{policies: policies})
}

// replace is the direct snapshot seam used by focused matcher tests.
func (s *Store) replace(policies []Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = make(map[string]Policy, len(policies))
	for _, policy := range policies {
		s.policies[policy.ResourceName()] = policy
	}
	s.publishLocked()
}

func sortPolicies(policies []Policy) {
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority > policies[j].Priority
		}
		if !policies[i].CreationTimestamp.Equal(&policies[j].CreationTimestamp) {
			return policies[i].CreationTimestamp.Before(&policies[j].CreationTimestamp)
		}
		return policies[i].ResourceName() < policies[j].ResourceName()
	})
}

// Authorize evaluates a CONNECT request against all selected egress policies.
// No selected policy is compatibility passthrough. Once at least one policy
// selects the caller, rules are evaluated in policy/rule order and no match is
// default deny.
func (s *Store) Authorize(pod inputs.Pod, req *httpreq.HTTPRequest) Decision {
	if req == nil || !strings.EqualFold(req.Method, "CONNECT") {
		return Decision{Allowed: true}
	}

	selected := false
	set := labels.Set(pod.Labels)
	current := s.snapshot.Load()
	for i := range current.policies {
		policy := &current.policies[i]
		if !policy.Global && policy.Namespace != pod.Namespace {
			continue
		}
		if policy.Selector == nil || !policy.Selector.Matches(set) {
			continue
		}
		// An ingress-only policy has no CONNECT egress effect.
		if policy.rules == nil {
			continue
		}
		selected = true
		for ruleIndex := range policy.rules {
			rule := &policy.rules[ruleIndex]
			if !rule.matches(req.Host, req.Port) {
				continue
			}
			return Decision{
				Enforced: true,
				Allowed:  rule.action == agentsv1alpha1.RuleActionAllow,
				Policy:   policy.displayName(),
				Rule:     ruleIndex,
			}
		}
	}
	if selected {
		return Decision{Enforced: true}
	}
	return Decision{Allowed: true}
}
