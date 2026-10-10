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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/client-go/util/workqueue"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

type bindingSync chan struct{}

func (s bindingSync) HasSynced() bool {
	select {
	case <-s:
		return true
	default:
		return false
	}
}

func (s bindingSync) WaitUntilSynced(stop <-chan struct{}) bool {
	select {
	case <-s:
		return true
	case <-stop:
		return false
	}
}

type bindingChange struct{ kind, key string }

// All processed inputs and membership updates belong to one worker.
type incrementalBindings struct {
	policies     map[string]PolicyAttachment
	targets      map[string]policyTarget
	policyScopes map[string]map[string]struct{}
	namespaces   map[string]map[string]struct{}
	output       krt.StaticCollection[Bindings]
	byPolicy     krt.Index[string, Bindings]
}

func newIncrementalBindings(workloads krt.Collection[model.Workload], attachments krt.Collection[PolicyAttachment], options krt.OptionsBuilder) krt.Collection[Bindings] {
	targets := krt.NewCollection(workloads, func(_ krt.HandlerContext, w model.Workload) *policyTarget {
		return &policyTarget{UID: w.UID, Namespace: w.Namespace, Labels: w.Labels}
	}, options.WithName("workload-policy-targets")...)
	ready := make(bindingSync)
	output := krt.NewMutableCollection[Bindings](ready, nil, options.WithName("workload-policy-bindings")...)
	state := incrementalBindings{
		policies: map[string]PolicyAttachment{}, targets: map[string]policyTarget{},
		policyScopes: map[string]map[string]struct{}{}, namespaces: map[string]map[string]struct{}{}, output: output,
		byPolicy: krt.NewIndex(output.AsCollection(), "bindingsByPolicy", func(b Bindings) []string {
			var keys []string
			for _, group := range b.Groups {
				for _, name := range group.Names {
					keys = append(keys, (model.PolicyRef{Kind: group.Kind, Name: name}).ResourceName())
				}
			}
			return keys
		}),
	}
	queue := workqueue.NewTyped[bindingChange]()
	policyEvents := attachments.RegisterBatch(func(events []krt.Event[PolicyAttachment]) {
		for _, event := range events {
			queue.Add(bindingChange{"policy", event.Latest().ResourceName()})
		}
	}, true)
	targetEvents := targets.RegisterBatch(func(events []krt.Event[policyTarget]) {
		for _, event := range events {
			queue.Add(bindingChange{"target", event.Latest().UID})
		}
	}, true)
	go func() { <-options.Stop(); queue.ShutDown() }()
	go func() {
		defer policyEvents.UnregisterHandler()
		defer targetEvents.UnregisterHandler()
		stop := options.Stop()
		if !attachments.WaitUntilSynced(stop) || !targets.WaitUntilSynced(stop) || !policyEvents.WaitUntilSynced(stop) || !targetEvents.WaitUntilSynced(stop) {
			return
		}
		// Seed policies first; each initial Workload needs only one complete match.
		for _, p := range attachments.List() {
			state.setPolicy(p.ResourceName(), &p)
		}
		for _, w := range targets.List() {
			select {
			case <-stop:
				return
			default:
			}
			state.updateTarget(w.UID, &w)
		}
		// Initial callbacks have queued their keys; reconcile them before exposing readiness.
		queue.Add(bindingChange{kind: "ready"})
		for {
			change, shutdown := queue.Get()
			if shutdown {
				return
			}
			select {
			case <-stop:
				queue.Done(change)
				return
			default:
			}
			switch change.kind {
			case "policy":
				state.updatePolicy(change.key, attachments.GetKey(change.key))
			case "target":
				state.updateTarget(change.key, targets.GetKey(change.key))
			case "ready":
				close(ready)
			}
			queue.Done(change)
		}
	}()
	return output.AsCollection()
}

func addBindingIndex(index map[string]map[string]struct{}, bucket, key string) {
	if index[bucket] == nil {
		index[bucket] = map[string]struct{}{}
	}
	index[bucket][key] = struct{}{}
}

func removeBindingIndex(index map[string]map[string]struct{}, bucket, key string) {
	delete(index[bucket], key)
	if len(index[bucket]) == 0 {
		delete(index, bucket)
	}
}

func (s *incrementalBindings) setPolicy(key string, current *PolicyAttachment) {
	if old, ok := s.policies[key]; ok {
		for _, scope := range attachmentIndexKeys(old) {
			removeBindingIndex(s.policyScopes, scope, key)
		}
	}
	delete(s.policies, key)
	if current != nil {
		s.policies[key] = *current
		for _, scope := range attachmentIndexKeys(*current) {
			addBindingIndex(s.policyScopes, scope, key)
		}
	}
}

func (s *incrementalBindings) updateTarget(key string, current *policyTarget) {
	if old, ok := s.targets[key]; ok {
		if current != nil && old.Equals(*current) {
			return
		}
		removeBindingIndex(s.namespaces, old.Namespace, key)
	}
	delete(s.targets, key)
	if current == nil {
		s.output.DeleteObject(key)
		return
	}
	s.targets[key] = *current
	addBindingIndex(s.namespaces, current.Namespace, key)
	matched := map[string]PolicyAttachment{}
	for _, scope := range []string{globalPolicyAttachmentIndexKey, namespacePolicyAttachmentKeyPrefix + current.Namespace} {
		for name := range s.policyScopes[scope] {
			p := s.policies[name]
			if p.selects(current.Namespace, current.Labels) {
				matched[name] = p
			}
		}
	}
	s.output.ConditionalUpdateObject(*bindingsFromMatches(key, matched))
}

func (s *incrementalBindings) updatePolicy(key string, current *PolicyAttachment) {
	old, exists := s.policies[key]
	if current == nil && !exists || current != nil && exists && old.Equals(*current) {
		return
	}
	previous := s.byPolicy.Lookup(key)
	s.setPolicy(key, current)
	selected := make(map[string]bool, len(previous))
	for _, binding := range previous {
		selected[binding.TargetUID] = false
	}
	if current != nil {
		if exists && apiequality.Semantic.DeepEqual(old.Target, current.Target) {
			for _, binding := range previous {
				selected[binding.TargetUID] = true
			}
		} else {
			check := func(uid string) {
				w := s.targets[uid]
				if current.selects(w.Namespace, w.Labels) {
					selected[uid] = true
				}
			}
			if current.Target.Global {
				for uid := range s.targets {
					check(uid)
				}
			} else {
				for _, namespace := range current.Target.Namespaces {
					for uid := range s.namespaces[namespace] {
						check(uid)
					}
				}
			}
		}
	}
	for uid, applies := range selected {
		matched := map[string]PolicyAttachment{}
		if binding := s.output.GetKey(uid); binding != nil {
			for _, group := range binding.Groups {
				for _, name := range group.Names {
					name := (model.PolicyRef{Kind: group.Kind, Name: name}).ResourceName()
					if name != key {
						matched[name] = s.policies[name]
					}
				}
			}
		}
		if applies {
			matched[key] = *current
		}
		s.output.ConditionalUpdateObject(*bindingsFromMatches(uid, matched))
	}
}
