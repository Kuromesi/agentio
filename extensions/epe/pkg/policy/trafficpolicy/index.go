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
	"fmt"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
)

type subjectKey struct {
	namespace string
	name      string
}
type compiledConfig struct {
	config egressauthz.Config
	err    error
}
type indexedWorkload struct {
	workload          *store.Resource
	workloadResources []store.Resource
	dependencies      []*store.Resource
	policies          []store.Resource
	named             []NamedPolicy
	compiled          compiledConfig
	err               error
}
type queryIndex struct {
	workloads map[subjectKey]*indexedWorkload
	err       error
}

// RegisterQueries adds Workload identity and ordered TrafficPolicy queries.
// Matching, dependency resolution and compilation stay outside the generic store.
func RegisterQueries(aggregate *store.Aggregate) {
	types := []store.Type{store.Workload, store.TrafficPolicy}
	aggregate.RegisterQueries(types, types, buildQueryIndex)
}

func buildQueryIndex(view *store.Snapshot, previous store.Query) store.Query {
	index := &queryIndex{workloads: map[subjectKey]*indexedWorkload{}}
	resources, err := view.List(store.Workload)
	if err != nil {
		index.err = err
		return index
	}
	old, _ := previous.(*queryIndex)
	for _, resource := range resources {
		w := resource.Value.(*workload.Workload)
		key := subjectKey{w.Namespace, w.Name}
		if _, found := index.workloads[key]; found {
			index.workloads[key] = &indexedWorkload{
				err: fmt.Errorf("ambiguous source Workload %s/%s", w.Namespace, w.Name),
			}
			continue
		}
		canonical, err := view.Get(resource.Key)
		if err != nil {
			index.err = err
			return index
		}
		var prior *indexedWorkload
		if old != nil {
			prior = old.workloads[key]
		}
		index.workloads[key] = buildWorkload(view, canonical, prior)
	}
	return index
}

func buildWorkload(view *store.Snapshot, resource *store.Resource, previous *indexedWorkload) *indexedWorkload {
	if previous != nil && previous.err == nil && previous.workload == resource {
		unchanged := true
		for _, dependency := range previous.dependencies {
			current, err := view.Get(dependency.Key)
			if err != nil || current != dependency {
				unchanged = false
				break
			}
		}
		if unchanged {
			return previous
		}
	}
	w := resource.Value.(*workload.Workload)
	entry := &indexedWorkload{workload: resource, workloadResources: []store.Resource{*resource}}
	refs, err := references(w)
	if err != nil {
		entry.err = err
		return entry
	}
	for _, name := range refs {
		key := store.Key{Type: store.TrafficPolicy, Name: name}
		policy, err := view.Get(key)
		if err != nil {
			entry.err = err
			return entry
		}
		if policy == nil {
			entry.err = &store.MissingResource{Key: key}
			return entry
		}
		entry.dependencies = append(entry.dependencies, policy)
	}

	for _, policy := range entry.dependencies {
		entry.policies = append(entry.policies, *policy)
		entry.named = append(entry.named, NamedPolicy{Name: policy.Key.Name, Policy: policy.Value.(*sec.TrafficPolicy)})
	}
	config, err := Compile(entry.named)
	entry.compiled = compiledConfig{config: config, err: err}
	return entry
}

func (i *queryIndex) forSubject(subject store.Subject) (*indexedWorkload, error) {
	if i.err != nil {
		return nil, i.err
	}
	entry := i.workloads[subjectKey{subject.Namespace, subject.Name}]
	if entry == nil {
		return nil, fmt.Errorf("source Workload %s/%s not found", subject.Namespace, subject.Name)
	}
	return entry, entry.err
}

func (i *queryIndex) ResourcesFor(typ store.Type, subject store.Subject) ([]store.Resource, error) {
	entry, err := i.forSubject(subject)
	// Workload lookup does not depend on its TrafficPolicy bindings.
	if typ == store.Workload && entry != nil && entry.workload != nil {
		return entry.workloadResources, nil
	}
	if err != nil {
		return nil, err
	}
	return entry.policies, nil
}
