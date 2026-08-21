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
// Profile matching uses an immutable label index to select candidates from Pod
// labels extracted from Envoy filter_state, then evaluates each candidate's
// complete Kubernetes selector at request time.
//
// The store is a materialized view of a krt compiled-profile collection: it
// uses a copy-on-write strategy with atomic.Pointer for lock-free reads, and
// each collection event batch is folded into a fresh snapshot under a mutex.
package profilestore

import (
	"maps"
	"sync"
	"sync/atomic"

	"istio.io/istio/extensions/epe/pkg/inputs"
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
// dynamic label-based matching at request time via ProfilesFor.
//
// Cluster-scoped GlobalSecurityProfiles are stored under an empty-namespace
// key and, unlike namespace-scoped SecurityProfiles, match pods in every
// namespace.
//
// Store is the read-only production surface consumed by the ext-proc data plane
// and admin endpoints. Writes are driven exclusively by RegisterCollection,
// which replays and then tails a krt compiled-profile collection in batches.
type Store interface {
	// List returns all installed profiles: selector-matched ones (both
	// namespace- and cluster-scoped) and per-Sandbox inline profiles.
	List() []*securityprofile.Profile

	// ProfilesFor returns the complete, ordered policy chain for one pod:
	// profiles whose selectors match pod.Labels (cluster-scoped
	// GlobalSecurityProfiles and namespace-scoped SecurityProfiles in
	// pod.Namespace, sorted by priority, creation time, name, namespace),
	// followed by the pod's own inline rule profile when one exists.
	// Inline profiles are keyed by exact identity — the Sandbox name is the
	// Pod name — and always evaluate after the selector-matched
	// administrator profiles. A zero pod.Name skips the inline lookup
	// (admin and debug paths that match by labels only).
	ProfilesFor(pod inputs.Pod) []*securityprofile.Profile
}

// profileSnapshot is an immutable point-in-time view of all profiles.
// It is replaced atomically on every write operation (copy-on-write).
//
// Selector profiles are indexed by namespace in byNamespace; cluster-scoped
// GlobalSecurityProfiles use an empty string as the namespace key. Per-Sandbox
// inline profiles live in inlineByKey, looked up by exact pod identity and
// never matched by labels.
//
// byNamespace is immutable once built and may be shared with the preceding
// snapshot when a batch left byKey untouched: nothing may mutate a
// profileIndex after buildSnapshot returns it.
type profileSnapshot struct {
	byKey       map[types.NamespacedName]*securityprofile.Profile
	byNamespace map[string]profileIndex
	inlineByKey map[types.NamespacedName]*securityprofile.Profile
}

func newEmptySnapshot() *profileSnapshot {
	return &profileSnapshot{
		byKey:       make(map[types.NamespacedName]*securityprofile.Profile),
		byNamespace: make(map[string]profileIndex),
		inlineByKey: make(map[types.NamespacedName]*securityprofile.Profile),
	}
}

// NewStore creates a new in-memory configuration store. Wire it to a
// compiled-profile collection with RegisterCollection.
func NewStore() *store {
	s := &store{degraded: newDegradedSets()}
	s.snapshot.Store(newEmptySnapshot())
	return s
}

type store struct {
	snapshot atomic.Pointer[profileSnapshot]
	mu       sync.Mutex // protects write path only
	// degraded is write-path state, guarded by mu: which sources are currently
	// stale, unenforced, or serving unresolved inputs. The gauges publish counts
	// from it, so the metric surface stays three series per gauge no matter how
	// many profiles the cluster holds.
	degraded degradedSets
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

// applyBatch folds one krt event batch into a new snapshot. Events route on
// the profile source: inline profiles maintain the identity-keyed map, and
// CRD profiles maintain the selector index. Invalid items of either source
// carry identity plus CompileError; they leave the prior effective entry
// untouched, and only a real source delete removes an installed profile.
func (s *store) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once per batch, not once per event: the gauges are counts, so only the
	// state after the whole batch is meaningful.
	defer s.degraded.publish()

	log := ctrllog.Log.WithName("profile")

	old := s.snapshot.Load()
	newByKey := make(map[types.NamespacedName]*securityprofile.Profile, len(old.byKey))
	maps.Copy(newByKey, old.byKey)
	newInline := make(map[types.NamespacedName]*securityprofile.Profile, len(old.inlineByKey))
	maps.Copy(newInline, old.inlineByKey)
	// Only byKey feeds the label index, so a batch that touched nothing but
	// inline profiles can carry the previous index forward instead of
	// rebuilding an identical one. Sandbox churn is the high-frequency event
	// source, and the rebuild is the expensive part of a write.
	selectorsChanged := false

	for _, ev := range events {
		if ev.Event == controllers.EventDelete {
			m := ev.Latest().Meta
			key := types.NamespacedName{Namespace: m.Namespace, Name: m.Name}
			// A deleted source leaves no degraded state behind, whichever map
			// it lived in.
			s.degraded.removed(degradedKeyFor(m))
			if m.Source == securityprofile.SourceInline {
				delete(newInline, key)
				continue
			}
			if _, installed := newByKey[key]; installed {
				delete(newByKey, key)
				selectorsChanged = true
			}
			continue
		}
		sp := ev.New
		key := types.NamespacedName{Namespace: sp.Meta.Namespace, Name: sp.Meta.Name}
		if sp.Meta.Source == securityprofile.SourceInline {
			// Same last-known-good contract as CRD profiles: an invalid
			// version leaves the prior effective one installed, and a first
			// version that never compiled installs nothing — the Sandbox
			// author's rules take effect only as published.
			if sp.CompileError != "" {
				profileCompileFailuresTotal.WithLabelValues(scopeInline).Inc()
				_, installed := newInline[key]
				s.degraded.rejected(degradedKeyFor(sp.Meta), installed)
				if installed {
					log.Error(nil, "inline security rules rejected; retaining last-known-good version",
						"sandbox", key.String(), "err", sp.CompileError)
				} else {
					log.Error(nil, "inline security rules rejected with no previous version installed; "+
						"none of them are in effect for this sandbox",
						"sandbox", key.String(), "err", sp.CompileError)
				}
				continue
			}
			s.degraded.installed(degradedKeyFor(sp.Meta), false)
			newInline[key] = sp
			continue
		}
		if sp.CompileError != "" {
			profileCompileFailuresTotal.WithLabelValues(profileScope(sp.Meta.Namespace)).Inc()
			// The two outcomes differ in severity and get separate gauges.
			// Stale means an older version is still enforcing; unenforced
			// means nothing of this profile is in effect at all, so the pods
			// it targets are unprotected.
			_, installed := newByKey[key]
			s.degraded.rejected(degradedKeyFor(sp.Meta), installed)
			if installed {
				log.Error(nil, "profile version rejected; retaining last-known-good version",
					"profile", key.String(), "err", sp.CompileError)
			} else {
				log.Error(nil, "profile rejected with no previous version installed; "+
					"none of its rules are in effect and the pods it selects are unprotected",
					"profile", key.String(), "err", sp.CompileError)
			}
			continue
		}
		s.degraded.installed(degradedKeyFor(sp.Meta), sp.InputsError != "")
		// A profile with unavailable inputs installs anyway: its rules enforce
		// and only inputs-dependent evaluations fail, resolved through the
		// consuming action's failure policy. The gauge and log are the
		// operator's signal that a referenced ConfigMap needs attention.
		if sp.InputsError != "" {
			log.Error(nil, "profile installed with unavailable inputs; rules enforce but "+
				"inputs-dependent evaluations fail per each action's failure strategy",
				"profile", key.String(), "err", sp.InputsError)
		}
		newByKey[key] = sp
		selectorsChanged = true
	}

	if selectorsChanged {
		s.snapshot.Store(buildSnapshot(newByKey, newInline))
		return
	}
	s.snapshot.Store(reuseSnapshot(old, newByKey, newInline))
}

// --- Read path (lock-free) ---

func (s *store) List() []*securityprofile.Profile {
	snap := s.snapshot.Load()
	result := make([]*securityprofile.Profile, 0, len(snap.byKey)+len(snap.inlineByKey))
	for _, p := range snap.byKey {
		result = append(result, p)
	}
	for _, p := range snap.inlineByKey {
		result = append(result, p)
	}
	return result
}

func (s *store) ProfilesFor(pod inputs.Pod) []*securityprofile.Profile {
	snap := s.snapshot.Load()

	ls := labels.Set(pod.Labels)
	matched := snap.byNamespace[GlobalProfileNamespace].appendMatches(ls, nil)
	if pod.Namespace != GlobalProfileNamespace {
		matched = snap.byNamespace[pod.Namespace].appendMatches(ls, matched)
	}
	// Candidate iteration crosses the fallback list and Pod label buckets, whose
	// order is not the policy evaluation order. Restore the shared precedence
	// contract after the global and namespaced matches have been merged.
	if len(matched) > 1 {
		securityprofile.SortProfiles(matched)
	}
	return appendInline(matched, snap, pod)
}

// appendInline adds the pod's own inline rule profile after the
// selector-matched administrator profiles: tenant rules must never evaluate
// ahead of them. A zero pod.Name (e.g. the admin listing endpoint) skips
// the lookup.
func appendInline(matched []*securityprofile.Profile, snap *profileSnapshot, pod inputs.Pod) []*securityprofile.Profile {
	if pod.Name == "" {
		return matched
	}
	if p, ok := snap.inlineByKey[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]; ok {
		return append(matched, p)
	}
	return matched
}

// reuseSnapshot builds the next snapshot from a batch that left byKey's
// contents untouched, carrying the label index forward instead of rebuilding an
// identical one. It exists so buildSnapshot stays the only place that decides
// what a snapshot is made of: a field added there must be handled here too, and
// a nil-returning compiler error is easier to notice than a silently zero field.
func reuseSnapshot(
	old *profileSnapshot,
	byKey, inlineByKey map[types.NamespacedName]*securityprofile.Profile,
) *profileSnapshot {
	return &profileSnapshot{
		byKey:       byKey,
		byNamespace: old.byNamespace,
		inlineByKey: inlineByKey,
	}
}

func buildSnapshot(byKey, inlineByKey map[types.NamespacedName]*securityprofile.Profile) *profileSnapshot {
	profilesByNamespace := make(map[string][]*securityprofile.Profile)

	for nn, sp := range byKey {
		profilesByNamespace[nn.Namespace] = append(profilesByNamespace[nn.Namespace], sp)
	}

	byNamespace := make(map[string]profileIndex, len(profilesByNamespace))
	for namespace, profiles := range profilesByNamespace {
		securityprofile.SortProfiles(profiles)
		byNamespace[namespace] = buildProfileIndex(profiles)
	}

	return &profileSnapshot{
		byKey:       byKey,
		byNamespace: byNamespace,
		inlineByKey: inlineByKey,
	}
}
