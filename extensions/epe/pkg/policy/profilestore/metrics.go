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

// metrics.go publishes what the store did with each compiled-profile event.
// Rejecting a version is not a data-plane error — the store keeps serving the
// previous one — so nothing on the request path notices. These series are the
// only signal an operator gets that a published profile never took effect.
package profilestore

import (
	"github.com/prometheus/client_golang/prometheus"

	"istio.io/istio/extensions/epe/pkg/metrics"
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
)

// Label values for the scope dimension. Bounded on purpose: the reason a
// profile failed to compile is an unbounded error string and belongs in the
// log line, never in a label.
const (
	scopeNamespaced = "namespaced"
	scopeGlobal     = "global"
	scopeInline     = "inline"
)

var (
	// profileCompileFailuresTotal counts source objects rejected at the
	// collection boundary. Every increment means a published profile version
	// did not take effect.
	profileCompileFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epe_profile_compile_failures_total",
			Help: "Profile versions rejected because they failed to compile.",
		},
		[]string{"scope"}, // namespaced | global
	)

	// profileStale counts sources whose newest published version failed to
	// compile while an earlier version stays installed. Alert on
	// `epe_profile_stale > 0`.
	profileStale = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_stale",
			Help: "Policy sources whose newest version was rejected and whose previous version is still being served.",
		},
		[]string{"scope"},
	)

	// profileUnenforced counts sources that exist in the API but have no
	// version installed at all, because the first version published for them
	// failed to compile. Nothing of that policy is in effect, so the pods it
	// targets are unprotected — the severe half of a compile failure, and the
	// one profileStale deliberately does not cover. Alert on
	// `epe_profile_unenforced > 0`.
	profileUnenforced = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_unenforced",
			Help: "Policy sources that failed to compile with no previous version installed, so none of their rules are in effect.",
		},
		[]string{"scope"},
	)

	// profileInputsUnavailable counts installed profiles whose declared inputs
	// could not be resolved — typically a referenced ConfigMap that does not
	// exist (or no longer exists). Their rules stay in effect; only evaluations
	// that read inputs fail, resolved through the consuming action's failure
	// policy. Alert on `epe_profile_inputs_unavailable > 0`.
	profileInputsUnavailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_inputs_unavailable",
			Help: "Installed profiles whose declared inputs are unresolved, so inputs-dependent evaluations fail per the consuming action's failure policy.",
		},
		[]string{"scope"},
	)
)

func init() {
	metrics.Registry.MustRegister(profileCompileFailuresTotal, profileStale, profileUnenforced, profileInputsUnavailable)
}

// profileScope maps a profile's namespace onto the bounded scope label.
// Cluster-scoped GlobalSecurityProfiles carry an empty namespace.
func profileScope(namespace string) string {
	if namespace == "" {
		return scopeGlobal
	}
	return scopeNamespaced
}

// degradedKey identifies one policy source in the degraded-state sets. Source
// is part of the key because a Sandbox and a SecurityProfile in one namespace
// may share a name, and each must be able to be degraded independently.
type degradedKey struct {
	source    string
	namespace string
	name      string
}

func degradedKeyFor(m securityprofile.Meta) degradedKey {
	return degradedKey{source: m.Source, namespace: m.Namespace, name: m.Name}
}

func (k degradedKey) scope() string {
	if k.source == securityprofile.SourceInline {
		return scopeInline
	}
	return profileScope(k.namespace)
}

// degradedSets records which policy sources are currently in each degraded
// state, so the gauges can publish a count per scope instead of one series per
// object.
//
// The identity deliberately does not reach the metric. A cluster can hold tens
// of thousands of SecurityProfiles and Sandboxes, and the failures these gauges
// describe are the systematic kind — one bad chart render, one Sandbox Manager
// schema change — so a per-identity label would mint a time series for every
// object in the cluster at exactly the moment the signal matters, multiplying
// scrape size and TSDB churn on a data-plane process. The counts answer "is
// anything degraded, and is it tenant or operator policy"; the log lines that
// accompany every transition name the object and the error.
//
// Memory is bounded by the number of degraded sources, not by the number of
// profiles: a healthy store holds three empty maps.
type degradedSets struct {
	stale             map[degradedKey]struct{}
	unenforced        map[degradedKey]struct{}
	inputsUnavailable map[degradedKey]struct{}
}

func newDegradedSets() degradedSets {
	return degradedSets{
		stale:             map[degradedKey]struct{}{},
		unenforced:        map[degradedKey]struct{}{},
		inputsUnavailable: map[degradedKey]struct{}{},
	}
}

// rejected records a version that failed to compile: stale when an earlier
// version is still installed, unenforced when none is. The inputs state is left
// alone — whatever is installed keeps serving with the inputs it resolved.
func (d degradedSets) rejected(k degradedKey, installed bool) {
	if installed {
		d.stale[k] = struct{}{}
		delete(d.unenforced, k)
		return
	}
	d.unenforced[k] = struct{}{}
	delete(d.stale, k)
}

// installed records a version that took effect, which clears both rejection
// states and refreshes the inputs state.
func (d degradedSets) installed(k degradedKey, inputsUnavailable bool) {
	delete(d.stale, k)
	delete(d.unenforced, k)
	if inputsUnavailable {
		d.inputsUnavailable[k] = struct{}{}
		return
	}
	delete(d.inputsUnavailable, k)
}

// removed forgets a source entirely, so a deleted object leaves nothing behind.
func (d degradedSets) removed(k degradedKey) {
	delete(d.stale, k)
	delete(d.unenforced, k)
	delete(d.inputsUnavailable, k)
}

// publish republishes all three gauges from the current sets. It runs once per
// event batch rather than once per event, and it always publishes every scope,
// including the zeros: a series that vanishes when healthy forces every alert
// to special-case absence.
func (d degradedSets) publish() {
	publishDegraded(profileStale, d.stale)
	publishDegraded(profileUnenforced, d.unenforced)
	publishDegraded(profileInputsUnavailable, d.inputsUnavailable)
}

func publishDegraded(g *prometheus.GaugeVec, set map[degradedKey]struct{}) {
	counts := map[string]int{scopeNamespaced: 0, scopeGlobal: 0, scopeInline: 0}
	for k := range set {
		counts[k.scope()]++
	}
	for scope, n := range counts {
		g.WithLabelValues(scope).Set(float64(n))
	}
}
