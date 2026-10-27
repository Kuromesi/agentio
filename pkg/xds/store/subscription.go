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

package store

import (
	"context"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Subscription receives changes for resources watched by a stream.
type Subscription interface {
	Watch(string)
	// WatchWorkload watches Address/Workload updates for a dedicated proxy.
	// Shared Service and Gateway dependencies remain broadly notified.
	WatchWorkload(typeURL, workloadUID string)
	// WatchNames updates interests in canonical wire names, without copying all
	// retained names on each demand. Alias/dependency watches must use Watch.
	WatchNames(typeURL string, wildcard bool, subscribed, unsubscribed []string)
	Updates() <-chan Update
}

type interest struct {
	wildcard    bool
	names       sets.Set[string]
	workloadUID string
}

type subscriber struct {
	updates   chan Update
	interests map[string]*interest
}

type subscription struct {
	store   *Store
	id      uint64
	updates <-chan Update
}

func (s *subscription) Updates() <-chan Update { return s.updates }

func (s *subscription) Watch(typeURL string) {
	s.WatchNames(typeURL, true, nil, nil)
}

// Called once for an Address/Workload watch with a fixed authenticated scope.
// Generators still enforce source, principal and explicit-name visibility.
func (s *subscription) WatchWorkload(typeURL, workloadUID string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	sub := s.store.subscribers[s.id]
	if sub == nil {
		return
	}
	sub.interests[typeURL] = &interest{workloadUID: workloadUID}
	addSubscriber(s.store.subscribersByType, typeURL, s.id, sub)
	addSubscriber(s.store.subscribersByWorkload, model.ResourceKey{TypeURL: typeURL, Name: workloadUID}, s.id, sub)
}

func (s *subscription) WatchNames(typeURL string, wildcard bool, subscribed, unsubscribed []string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	sub := s.store.subscribers[s.id]
	// Context cancellation may have released this stream.
	if sub == nil {
		return
	}
	watch := sub.interests[typeURL]
	if watch == nil {
		watch = &interest{wildcard: true, names: sets.New[string]()}
		sub.interests[typeURL] = watch
		addSubscriber(s.store.subscribersByType, typeURL, s.id, sub)
	}
	if !watch.wildcard {
		if wildcard {
			for name := range watch.names {
				removeSubscriber(s.store.subscribersByName, model.ResourceKey{TypeURL: typeURL, Name: name}, s.id)
			}
		} else {
			for _, name := range unsubscribed {
				removeSubscriber(s.store.subscribersByName, model.ResourceKey{TypeURL: typeURL, Name: name}, s.id)
			}
		}
	}
	for _, name := range subscribed {
		if name != "*" {
			watch.names.Insert(name)
		}
	}
	watch.names.DeleteAll(unsubscribed...)
	if wildcard {
		addSubscriber(s.store.wildcardSubscribersByType, typeURL, s.id, sub)
	} else {
		removeSubscriber(s.store.wildcardSubscribersByType, typeURL, s.id)
		if watch.wildcard {
			for name := range watch.names {
				addSubscriber(s.store.subscribersByName, model.ResourceKey{TypeURL: typeURL, Name: name}, s.id, sub)
			}
		} else {
			for _, name := range subscribed {
				if watch.names.Contains(name) {
					addSubscriber(s.store.subscribersByName, model.ResourceKey{TypeURL: typeURL, Name: name}, s.id, sub)
				}
			}
		}
	}
	watch.wildcard = wildcard
}

func addSubscriber[K comparable](index map[K]map[uint64]*subscriber, key K, id uint64, sub *subscriber) {
	if index[key] == nil {
		index[key] = make(map[uint64]*subscriber)
	}
	index[key][id] = sub
}

func removeSubscriber[K comparable](index map[K]map[uint64]*subscriber, key K, id uint64) {
	delete(index[key], id)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}

// Subscribe registers a watcher that is released when ctx is canceled.
func (s *Store) Subscribe(ctx context.Context) Subscription {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	updates := make(chan Update, 1)
	s.subscribers[id] = &subscriber{updates: updates, interests: make(map[string]*interest)}
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		sub := s.subscribers[id]
		for typeURL, watch := range sub.interests {
			removeSubscriber(s.subscribersByType, typeURL, id)
			removeSubscriber(s.wildcardSubscribersByType, typeURL, id)
			if watch.workloadUID != "" {
				removeSubscriber(
					s.subscribersByWorkload,
					model.ResourceKey{TypeURL: typeURL, Name: watch.workloadUID},
					id,
				)
			}
			if !watch.wildcard {
				for name := range watch.names {
					removeSubscriber(s.subscribersByName, model.ResourceKey{TypeURL: typeURL, Name: name}, id)
				}
			}
		}
		delete(s.subscribers, id)
		s.mu.Unlock()
	}()
	return &subscription{store: s, id: id, updates: updates}
}

// Route before either coalescing boundary. Named watchers retain only their
// candidates, including old identities needed for deletions and migrations.
func (s *Store) notificationsLocked(update Update) map[*subscriber]*Update {
	result := make(map[*subscriber]*Update)
	add := func(sub *subscriber, update *Update) {
		if pending, found := result[sub]; found {
			merged := Merge(*pending, *update)
			update = &merged
		}
		result[sub] = update
	}
	if update.full && len(update.fullTypes) == 0 {
		for _, sub := range s.subscribers {
			result[sub] = &update
		}
		return result
	}
	// Keep the shared notification path when no affected type needs named
	// routing, including full refreshes. Ordinary wildcard pushes do not need
	// per-type copies or per-connection merges.
	named := false
	for typeURL := range update.affectedTypes {
		if !update.FullFor(typeURL) && len(s.subscribersByType[typeURL]) != len(s.wildcardSubscribersByType[typeURL]) {
			named = true
			break
		}
	}
	if !named {
		for _, types := range []sets.Set[string]{update.affectedTypes, update.fullTypes} {
			for typeURL := range types {
				for _, sub := range s.subscribersByType[typeURL] {
					result[sub] = &update
				}
			}
		}
		return result
	}

	types := sets.New[string]()
	types.Merge(update.affectedTypes)
	types.Merge(update.fullTypes)
	for typeURL := range types {
		if update.FullFor(typeURL) {
			typed := Update{version: update.version, full: true, fullTypes: sets.New(typeURL)}
			for _, sub := range s.subscribersByType[typeURL] {
				add(sub, &typed)
			}
			continue
		}
		candidates := update.Candidates(typeURL)
		typed := candidateUpdate(update.version, typeURL, candidates)
		for _, sub := range s.wildcardSubscribersByType[typeURL] {
			add(sub, &typed)
		}
		selected := make(map[*subscriber][]Candidate)
		s.selectNamedCandidatesLocked(typeURL, candidates, selected)

		for sub, candidates := range selected {
			selectedUpdate := candidateUpdate(update.version, typeURL, candidates)
			add(sub, &selectedUpdate)
		}
	}
	return result
}

func (s *Store) selectNamedCandidatesLocked(
	typeURL string,
	candidates []Candidate,
	selected map[*subscriber][]Candidate,
) {
	selectCandidate := func(sub *subscriber, candidate Candidate) {
		previous := selected[sub]
		// Several historical identities can route the same candidate here.
		if len(previous) == 0 || previous[len(previous)-1].Key != candidate.Key {
			selected[sub] = append(previous, candidate)
		}
	}
	for _, candidate := range candidates {
		for _, identity := range candidate.Identities {
			for _, sub := range s.subscribersByName[model.ResourceKey{TypeURL: typeURL, Name: identity.Name}] {
				selectCandidate(sub, candidate)
			}
		}
		if len(s.subscribersByWorkload) != 0 && (typeURL == model.AddressType || typeURL == model.WorkloadType) {
			shared := false
			for _, identity := range candidate.Identities {
				workload := identity.Facts.Workload
				if workload == nil || identity.Facts.GatewayOwner != "" {
					shared = true
					break
				}
				for _, sub := range s.subscribersByWorkload[model.ResourceKey{TypeURL: typeURL, Name: workload.WorkloadUID}] {
					selectCandidate(sub, candidate)
				}
			}
			// Keep shared dependency visibility and withdrawal in the generator.
			if shared {
				for _, sub := range s.subscribersByType[typeURL] {
					if sub.interests[typeURL].workloadUID != "" {
						selectCandidate(sub, candidate)
					}
				}
			}
		}
	}
}

func candidateUpdate(version, typeURL string, candidates []Candidate) Update {
	keyType := typeURL
	if keyType == model.WorkloadType {
		keyType = model.AddressType
	}
	affected := sets.New(typeURL)
	if typeURL == model.AddressType {
		affected.Insert(model.WorkloadType)
	}
	return Update{version: version, candidates: map[string][]Candidate{keyType: candidates}, affectedTypes: affected}
}
