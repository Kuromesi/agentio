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
	// List returns all installed profiles: selector-matched ones (both
	// namespace- and cluster-scoped) and per-Sandbox inline profiles.
	List() []*securityprofile.Profile

	// Matches returns the profiles that apply to the given pod: profiles
	// whose selectors match the pod labels (cluster-scoped
	// GlobalSecurityProfiles and namespace-scoped SecurityProfiles in
	// podNamespace, sorted by priority, creation time, name, namespace),
	// followed by the pod's own inline rule profile when one exists.
	// Inline profiles are keyed by exact identity — the Sandbox name is the
	// Pod name — and always evaluate after the selector-matched
	// administrator profiles. An empty podName skips the inline lookup.
	Matches(podName, podNamespace string, podLabels map[string]string) []*securityprofile.Profile
}

// profileSnapshot is an immutable point-in-time view of all profiles.
// It is replaced atomically on every write operation (copy-on-write).
//
// Selector profiles are indexed by namespace in byNamespace; cluster-scoped
// GlobalSecurityProfiles use an empty string as the namespace key. Per-Sandbox
// inline profiles live in inlineByKey, looked up by exact pod identity and
// never matched by labels.
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

// applyBatch folds one krt event batch into a new snapshot. Events route on
// the profile source: inline profiles maintain the identity-keyed map, and
// CRD profiles maintain the selector index. Invalid CRD profile items carry
// identity plus CompileError; they leave the prior effective entry untouched,
// and only a real source delete removes an installed profile. Inline
// profiles have no invalid form here — a compile failure emits no item.
func (s *store) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log := ctrllog.Log.WithName("profile")

	old := s.snapshot.Load()
	newByKey := make(map[types.NamespacedName]*securityprofile.Profile, len(old.byKey))
	maps.Copy(newByKey, old.byKey)
	newInline := make(map[types.NamespacedName]*securityprofile.Profile, len(old.inlineByKey))
	maps.Copy(newInline, old.inlineByKey)

	for _, ev := range events {
		if ev.Event == controllers.EventDelete {
			m := ev.Latest().Meta
			key := types.NamespacedName{Namespace: m.Namespace, Name: m.Name}
			if m.Source == securityprofile.SourceInline {
				delete(newInline, key)
				continue
			}
			delete(newByKey, key)
			profileStale.DeleteLabelValues(m.Namespace, m.Name)
			profileUnenforced.DeleteLabelValues(m.Namespace, m.Name)
			profileInputsUnavailable.DeleteLabelValues(m.Namespace, m.Name)
			continue
		}
		sp := ev.New
		key := types.NamespacedName{Namespace: sp.Meta.Namespace, Name: sp.Meta.Name}
		if sp.Meta.Source == securityprofile.SourceInline {
			if sp.CompileError == "" {
				newInline[key] = sp
			}
			continue
		}
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
		// A profile with unavailable inputs installs anyway: its rules enforce
		// and only inputs-dependent evaluations fail, resolved through the
		// consuming action's failure policy. The gauge and log are the
		// operator's signal that a referenced ConfigMap needs attention.
		if sp.InputsError != "" {
			profileInputsUnavailable.WithLabelValues(sp.Meta.Namespace, sp.Meta.Name).Set(1)
			log.Error(nil, "profile installed with unavailable inputs; rules enforce but "+
				"inputs-dependent evaluations fail per each action's failure strategy",
				"profile", key.String(), "err", sp.InputsError)
		} else {
			profileInputsUnavailable.DeleteLabelValues(sp.Meta.Namespace, sp.Meta.Name)
		}
		newByKey[key] = sp
	}

	s.snapshot.Store(buildSnapshot(newByKey, newInline))
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

func (s *store) Matches(podName, podNamespace string, podLabels map[string]string) []*securityprofile.Profile {
	snap := s.snapshot.Load()

	ls := labels.Set(podLabels)
	matched := snap.byNamespace[GlobalProfileNamespace].appendMatches(podLabels, ls, nil)
	if podNamespace != GlobalProfileNamespace {
		matched = snap.byNamespace[podNamespace].appendMatches(podLabels, ls, matched)
	}
	if len(matched) == 0 {
		return appendInline(nil, snap, podName, podNamespace)
	}
	// Candidate iteration crosses the fallback list and Pod label buckets, whose
	// order is not the policy evaluation order. Restore the shared precedence
	// contract after the global and namespaced matches have been merged.
	if len(matched) > 1 {
		securityprofile.SortProfiles(matched)
	}
	return appendInline(matched, snap, podName, podNamespace)
}

// appendInline adds the pod's own inline rule profile after the
// selector-matched administrator profiles: tenant rules must never evaluate
// ahead of them. An empty podName (e.g. the admin listing endpoint) skips
// the lookup.
func appendInline(matched []*securityprofile.Profile, snap *profileSnapshot, podName, podNamespace string) []*securityprofile.Profile {
	if podName == "" {
		return matched
	}
	if p, ok := snap.inlineByKey[types.NamespacedName{Namespace: podNamespace, Name: podName}]; ok {
		return append(matched, p)
	}
	return matched
}

// buildSnapshot constructs a complete profileSnapshot from the selector and
// inline profile maps. Every selector profile is indexed under its namespace
// in byNamespace; entries with an empty Namespace are cluster-scoped
// GlobalSecurityProfiles and land under the "" key, which Matches merges into
// every namespace's result. Inline profiles are carried as-is; they are
// looked up by identity only.
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
