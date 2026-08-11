// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Package profilestore provides an in-memory store for SecurityProfiles.
// Profile matching is performed dynamically at request time using pod labels
// extracted from Envoy filter_state, rather than maintaining a pre-computed
// pod-to-profile index.
//
// The store is a materialized view of a krt compiled-profile collection: it
// uses a copy-on-write strategy with atomic.Pointer for lock-free reads, and
// each collection event batch is folded into a fresh snapshot under a mutex.
package profilestore

import (
	"maps"
	"sync"
	"sync/atomic"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	GlobalProfileNamespace = ""
)

// Store is a thread-safe in-memory store for SecurityProfiles and
// GlobalSecurityProfiles. It maintains a simple profile index and performs
// dynamic label-based matching at request time via Matches.
//
// Cluster-scoped GlobalSecurityProfiles are stored under an empty-namespace
// key and, unlike namespace-scoped SecurityProfiles, match pods in every
// namespace.
//
// Store is the read-only production surface consumed by the ext-proc data plane
// and admin endpoints. Writes are driven exclusively by RegisterCollection,
// which replays and then tails a krt compiled-profile collection in batches.
type Store interface {
	// List returns all profiles, both namespace- and cluster-scoped.
	List() []*securityprofile.Profile

	// Matches returns the profiles whose selectors match the given pod
	// labels. Both cluster-scoped GlobalSecurityProfiles and namespace-scoped
	// SecurityProfiles in podNamespace are considered. Returns profiles sorted
	// by priority (lower first), then creation time, then name, then namespace.
	Matches(podNamespace string, podLabels map[string]string) []*securityprofile.Profile
}

// profileSnapshot is an immutable point-in-time view of all profiles.
// It is replaced atomically on every write operation (copy-on-write).
//
// Profiles are indexed by namespace in byNamespace. Cluster-scoped
// GlobalSecurityProfiles use an empty string as the namespace key.
// All slices are pre-sorted by the shared profile comparator.
type profileSnapshot struct {
	byKey       map[types.NamespacedName]*securityprofile.Profile
	byNamespace map[string][]*securityprofile.Profile
}

func newEmptySnapshot() *profileSnapshot {
	return &profileSnapshot{
		byKey:       make(map[types.NamespacedName]*securityprofile.Profile),
		byNamespace: make(map[string][]*securityprofile.Profile),
	}
}

// NewStore creates a new in-memory configuration store. Wire it to a
// compiled-profile collection with RegisterCollection.
func NewStore() *store {
	s := &store{}
	s.snapshot.Store(newEmptySnapshot())
	return s
}

type store struct {
	snapshot atomic.Pointer[profileSnapshot]
	mu       sync.Mutex // protects write path only
}

// RegisterCollection materializes the compiled-profile collection into the
// store's snapshot. It registers a batch handler with initial-state replay,
// so the current collection contents are applied immediately and every
// subsequent krt event batch triggers one copy-on-write snapshot rebuild.
// The returned registration's WaitUntilSynced gates readiness on the initial
// replay having been delivered.
func (s *store) RegisterCollection(profiles krt.Collection[securityprofile.Profile]) krt.HandlerRegistration {
	return profiles.RegisterBatch(s.applyBatch, true)
}

// applyBatch folds one krt event batch into a new snapshot. Invalid profile
// items carry identity plus CompileError; they leave the prior effective
// entry untouched. Only a real source delete removes an installed profile.
func (s *store) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log := ctrllog.Log.WithName("profile")

	old := s.snapshot.Load()
	newByKey := make(map[types.NamespacedName]*securityprofile.Profile, len(old.byKey))
	maps.Copy(newByKey, old.byKey)

	for _, ev := range events {
		if ev.Event == controllers.EventDelete {
			m := ev.Latest().Meta
			delete(newByKey, types.NamespacedName{Namespace: m.Namespace, Name: m.Name})
			profileStale.DeleteLabelValues(m.Namespace, m.Name)
			profileUnenforced.DeleteLabelValues(m.Namespace, m.Name)
			continue
		}
		sp := ev.New
		key := types.NamespacedName{Namespace: sp.Meta.Namespace, Name: sp.Meta.Name}
		if sp.CompileError != "" {
			profileCompileFailuresTotal.WithLabelValues(profileScope(sp.Meta.Namespace)).Inc()
			// The two outcomes differ in severity and get separate series.
			// Stale means an older version is still enforcing; unenforced
			// means nothing of this profile is in effect at all, so the pods
			// it targets are unprotected.
			if _, installed := newByKey[key]; installed {
				profileStale.WithLabelValues(sp.Meta.Namespace, sp.Meta.Name).Set(1)
				log.Error(nil, "profile version rejected; retaining last-known-good version",
					"profile", key.String(), "err", sp.CompileError)
			} else {
				profileUnenforced.WithLabelValues(sp.Meta.Namespace, sp.Meta.Name).Set(1)
				log.Error(nil, "profile rejected with no previous version installed; "+
					"none of its rules are in effect and the pods it selects are unprotected",
					"profile", key.String(), "err", sp.CompileError)
			}
			continue
		}
		profileStale.DeleteLabelValues(sp.Meta.Namespace, sp.Meta.Name)
		profileUnenforced.DeleteLabelValues(sp.Meta.Namespace, sp.Meta.Name)
		newByKey[key] = sp
	}

	s.snapshot.Store(buildSnapshot(newByKey))
}

// --- Read path (lock-free) ---

func (s *store) List() []*securityprofile.Profile {
	snap := s.snapshot.Load()
	result := make([]*securityprofile.Profile, 0, len(snap.byKey))
	for _, p := range snap.byKey {
		result = append(result, p)
	}
	return result
}

func (s *store) Matches(podNamespace string, podLabels map[string]string) []*securityprofile.Profile {
	snap := s.snapshot.Load()

	ls := labels.Set(podLabels)
	// Cluster-scoped profiles (empty namespace) match pods in every namespace.
	global := snap.byNamespace[GlobalProfileNamespace]

	// When podNamespace is itself the cluster scope, byNamespace[podNamespace]
	// aliases the global slice; skip the second pass so global profiles are not
	// matched and appended twice. Callers currently never pass an empty
	// namespace, but the guard keeps the function self-consistent regardless.
	var nsProfiles []*securityprofile.Profile
	if podNamespace != GlobalProfileNamespace {
		nsProfiles = snap.byNamespace[podNamespace]
	}

	matched := make([]*securityprofile.Profile, 0, len(global)+len(nsProfiles))
	globalMatches := 0
	for _, sp := range global {
		if sp.Selector.Matches(ls) {
			matched = append(matched, sp)
			globalMatches++
		}
	}
	for _, sp := range nsProfiles {
		if sp.Selector.Matches(ls) {
			matched = append(matched, sp)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	// Each snapshot slice is already sorted by securityprofile.SortProfiles, and filtering
	// preserves that order. Only when both the cluster- and namespace-scoped
	// runs contribute must the merged set be re-sorted so they interleave by the
	// shared comparator rather than global-always-first; a single contributing
	// run is already in evaluation order.
	if globalMatches > 0 && globalMatches < len(matched) {
		securityprofile.SortProfiles(matched)
	}
	return matched
}

// buildSnapshot constructs a complete profileSnapshot from a byKey map. Every
// profile is indexed under its namespace in byNamespace; entries with an empty
// Namespace are cluster-scoped GlobalSecurityProfiles and land under the ""
// key, which Matches merges into every namespace's result. Each
// per-namespace slice is sorted by securityprofile.SortProfiles.
func buildSnapshot(byKey map[types.NamespacedName]*securityprofile.Profile) *profileSnapshot {
	byNamespace := make(map[string][]*securityprofile.Profile)

	for nn, sp := range byKey {
		byNamespace[nn.Namespace] = append(byNamespace[nn.Namespace], sp)
	}

	for _, profiles := range byNamespace {
		securityprofile.SortProfiles(profiles)
	}

	return &profileSnapshot{
		byKey:       byKey,
		byNamespace: byNamespace,
	}
}
