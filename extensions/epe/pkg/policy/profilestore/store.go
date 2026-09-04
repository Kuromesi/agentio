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

	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
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
	// namespace- and cluster-scoped) and per-Sandbox pod-matched profiles.
	List() []*securityprofile.Profile

	// ProfilesFor returns the complete, ordered policy chain for one pod:
	// profiles whose selectors match pod.Labels (cluster-scoped
	// GlobalSecurityProfiles and namespace-scoped SecurityProfiles in
	// pod.Namespace, sorted by priority, creation time, name, namespace),
	// followed by the pod's own profile when one exists. Pod-matched
	// profiles are keyed by exact identity — the Sandbox name is the
	// Pod name — and always evaluate after the selector-matched
	// administrator profiles. A zero pod.Name skips the identity lookup
	// (admin and debug paths that match by labels only).
	ProfilesFor(pod inputs.Pod) []*securityprofile.Profile
}

// profileKey identifies one installed profile. The match mode belongs in the
// key for two reasons: a Sandbox and a SecurityProfile in one namespace may
// share a name, and the mode is what decides how the profile is found — by
// exact Pod identity, or through the label index. It is a uint8 rather than a
// string because this key is copied for every entry on every write.
type profileKey struct {
	match     securityprofile.MatchMode
	namespace string
	name      string
}

func keyFor(m securityprofile.Meta) profileKey {
	return profileKey{match: m.Match, namespace: m.Namespace, name: m.Name}
}

// name2 is the identity half of the key, which is what each per-mode map is
// keyed by. The mode selects the map, so it must not also sit in the key.
func (k profileKey) name2() types.NamespacedName {
	return types.NamespacedName{Namespace: k.namespace, Name: k.name}
}

// scope maps the key onto the bounded metric scope label.
func (k profileKey) scope() string {
	if k.match == securityprofile.MatchPod {
		return scopePod
	}
	return profileScope(k.namespace)
}

// installedSet holds every installed profile, in one identity-keyed map per
// match mode. Callers address it by profileKey and never choose a map, so the
// write path treats every policy source identically; the split is what keeps
// the two lookups apart.
//
// Two maps rather than one keyed by (mode, namespace, name): the whole set is
// copied on every write, and folding the mode into the key grew it from two
// words to three, which measured ~17% slower and ~16% more allocation per batch
// at ten thousand profiles.
type installedSet struct {
	selector map[types.NamespacedName]*securityprofile.Profile
	pod      map[types.NamespacedName]*securityprofile.Profile
}

func newInstalledSet(selectorCap, podCap int) installedSet {
	return installedSet{
		selector: make(map[types.NamespacedName]*securityprofile.Profile, selectorCap),
		pod:      make(map[types.NamespacedName]*securityprofile.Profile, podCap),
	}
}

// clone is the copy-on-write step: the caller mutates the copy and publishes it.
func (set installedSet) clone() installedSet {
	next := newInstalledSet(len(set.selector), len(set.pod))
	maps.Copy(next.selector, set.selector)
	maps.Copy(next.pod, set.pod)
	return next
}

func (set installedSet) mapFor(match securityprofile.MatchMode) map[types.NamespacedName]*securityprofile.Profile {
	if match == securityprofile.MatchPod {
		return set.pod
	}
	return set.selector
}

func (set installedSet) get(k profileKey) (*securityprofile.Profile, bool) {
	p, ok := set.mapFor(k.match)[k.name2()]
	return p, ok
}

func (set installedSet) put(k profileKey, sp *securityprofile.Profile) {
	set.mapFor(k.match)[k.name2()] = sp
}

// remove reports whether anything was installed under the key.
func (set installedSet) remove(k profileKey) bool {
	m := set.mapFor(k.match)
	key := k.name2()
	if _, ok := m[key]; !ok {
		return false
	}
	delete(m, key)
	return true
}

func (set installedSet) len() int { return len(set.selector) + len(set.pod) }

// profileSnapshot is an immutable point-in-time view of all profiles.
// It is replaced atomically on every write operation (copy-on-write).
//
// installed is the storage. A pod-matched profile needs no index of its own,
// because its key *is* its lookup — exact Pod identity. Selector profiles do,
// so selectorIndex is the label index derived from installed.selector, keyed by
// namespace with cluster-scoped GlobalSecurityProfiles under the empty string.
//
// Keeping the two lookups apart is a security property, not an optimization: an
// identity match must never be reachable through a label, which a workload can
// influence.
//
// selectorIndex is immutable once built and may be shared with the preceding
// snapshot when a batch changed no selector profile: nothing may mutate a
// profileIndex after buildSnapshot returns it.
type profileSnapshot struct {
	installed     installedSet
	selectorIndex map[string]profileIndex
}

func newEmptySnapshot() *profileSnapshot {
	return &profileSnapshot{
		installed:     newInstalledSet(0, 0),
		selectorIndex: make(map[string]profileIndex),
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

// applyBatch folds one krt event batch into a new snapshot. Every source is
// handled the same way — an invalid item carries identity plus CompileError and
// leaves the prior effective entry untouched, and only a real source delete
// removes an installed profile. The source affects one thing here: whether the
// derived label index has to be rebuilt.
func (s *store) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once per batch, not once per event: the gauges are counts, so only the
	// state after the whole batch is meaningful.
	defer s.degraded.publish()

	log := ctrllog.Log.WithName("profile")

	old := s.snapshot.Load()
	installed := old.installed.clone()
	// Only selector profiles feed the label index, so a batch that touched
	// nothing but per-Sandbox profiles can carry the previous index forward
	// instead of rebuilding an identical one. Sandbox churn is the
	// high-frequency event source, and the rebuild is the expensive part of a
	// write.
	selectorsChanged := false

	for _, ev := range events {
		if ev.Event == controllers.EventDelete {
			key := keyFor(ev.Latest().Meta)
			// A deleted source leaves no degraded state behind.
			s.degraded.removed(key)
			if installed.remove(key) {
				selectorsChanged = selectorsChanged || key.match == securityprofile.MatchSelector
			}
			continue
		}
		sp := ev.New
		key := keyFor(sp.Meta)
		// One last-known-good contract for every source: an invalid version
		// leaves the prior effective one installed, and a first version that
		// never compiled installs nothing.
		if sp.CompileError != "" {
			profileCompileFailuresTotal.WithLabelValues(key.scope()).Inc()
			_, wasInstalled := installed.get(key)
			s.degraded.rejected(key, wasInstalled)
			// The two outcomes differ in severity and get separate gauges.
			// Stale means an older version is still enforcing; unenforced means
			// nothing of this policy is in effect at all — for a selector
			// profile the Pods it targets are unprotected, for a per-Sandbox
			// one that Sandbox has none of its own rules.
			if wasInstalled {
				log.Error(nil, "policy version rejected; retaining last-known-good version",
					"profile", sp.ResourceName(), "scope", key.scope(), "error", sp.CompileError)
			} else {
				log.Error(nil, "policy version rejected with no previous version installed; "+
					"none of its rules are in effect",
					"profile", sp.ResourceName(), "scope", key.scope(), "error", sp.CompileError)
			}
			continue
		}
		s.degraded.installed(key, sp.InputsError != "")
		// A profile with unavailable inputs installs anyway: its rules enforce
		// and only inputs-dependent evaluations fail, resolved through the
		// consuming action's failure policy. The gauge and log are the
		// operator's signal that a referenced ConfigMap needs attention.
		if sp.InputsError != "" {
			log.Error(nil, "profile installed with unavailable inputs; rules enforce but "+
				"inputs-dependent evaluations fail per each action's failure strategy",
				"profile", sp.ResourceName(), "error", sp.InputsError)
		}
		installed.put(key, sp)
		selectorsChanged = selectorsChanged || key.match == securityprofile.MatchSelector
	}

	if selectorsChanged {
		s.snapshot.Store(buildSnapshot(installed))
		return
	}
	s.snapshot.Store(reuseSnapshot(old, installed))
}

// --- Read path (lock-free) ---

func (s *store) List() []*securityprofile.Profile {
	snap := s.snapshot.Load()
	result := make([]*securityprofile.Profile, 0, snap.installed.len())
	for _, p := range snap.installed.selector {
		result = append(result, p)
	}
	for _, p := range snap.installed.pod {
		result = append(result, p)
	}
	return result
}

func (s *store) ProfilesFor(pod inputs.Pod) []*securityprofile.Profile {
	snap := s.snapshot.Load()

	ls := labels.Set(pod.Labels)
	matched := snap.selectorIndex[GlobalProfileNamespace].appendMatches(ls, nil)
	if pod.Namespace != GlobalProfileNamespace {
		matched = snap.selectorIndex[pod.Namespace].appendMatches(ls, matched)
	}
	// Candidate iteration crosses the fallback list and Pod label buckets, whose
	// order is not the policy evaluation order. Restore the shared precedence
	// contract after the global and namespaced matches have been merged.
	if len(matched) > 1 {
		securityprofile.SortProfiles(matched)
	}
	return appendPodProfile(matched, snap, pod)
}

// appendPodProfile adds the pod's own profile after the selector-matched
// administrator profiles: tenant rules must never evaluate ahead of them. It is
// one map lookup, because identity is the storage key. A zero pod.Name (e.g.
// the admin listing endpoint) skips the lookup.
func appendPodProfile(matched []*securityprofile.Profile, snap *profileSnapshot, pod inputs.Pod) []*securityprofile.Profile {
	if pod.Name == "" {
		return matched
	}
	if p, ok := snap.installed.pod[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]; ok {
		return append(matched, p)
	}
	return matched
}

// reuseSnapshot builds the next snapshot from a batch that changed no selector
// profile, carrying the label index forward instead of rebuilding an identical
// one. It exists so buildSnapshot stays the only place that decides what a
// snapshot is made of: a field added there must be handled here too, and a
// compiler error is easier to notice than a silently zero field.
func reuseSnapshot(old *profileSnapshot, installed installedSet) *profileSnapshot {
	return &profileSnapshot{installed: installed, selectorIndex: old.selectorIndex}
}

// buildSnapshot takes ownership of installed and derives the label index from
// its selector half. Pod-matched profiles are not in it: they are found by
// identity, and letting them into the label index is exactly the confusion the
// two lookups exist to prevent.
func buildSnapshot(installed installedSet) *profileSnapshot {
	profilesByNamespace := make(map[string][]*securityprofile.Profile)
	for nn, sp := range installed.selector {
		profilesByNamespace[nn.Namespace] = append(profilesByNamespace[nn.Namespace], sp)
	}

	selectorIndex := make(map[string]profileIndex, len(profilesByNamespace))
	for namespace, profiles := range profilesByNamespace {
		securityprofile.SortProfiles(profiles)
		selectorIndex[namespace] = buildProfileIndex(profiles)
	}

	return &profileSnapshot{installed: installed, selectorIndex: selectorIndex}
}
