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
)

// Label values for the scope dimension. Bounded on purpose: the reason a
// profile failed to compile is an unbounded error string and belongs in the
// log line, never in a label.
const (
	scopeNamespaced = "namespaced"
	scopeGlobal     = "global"
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

	// profileStale marks identities whose newest published version failed to
	// compile while an earlier version stays installed. The series exists only
	// while that is true, so absence means healthy and deleted profiles leave
	// nothing behind: alert on `epe_profile_stale == 1`.
	//
	// Cardinality is one series per stale profile. Profiles are operator
	// authored and bounded, and only the stale ones are ever present.
	profileStale = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_stale",
			Help: "Profiles whose newest version was rejected and whose previous version is still being served.",
		},
		[]string{"namespace", "name"},
	)

	// profileUnenforced marks identities that exist in the API but have no
	// version installed at all, because the first version published for them
	// failed to compile. Nothing of the profile is in effect, so the pods it
	// targets are unprotected — the severe half of a compile failure, and the
	// one profileStale deliberately does not cover.
	//
	// It is per-identity because the compile counter is not: an operator
	// seeing that counter move cannot tell which profile stopped enforcing.
	// Alert on `epe_profile_unenforced == 1`; absence means
	// healthy, and deleted profiles leave nothing behind.
	profileUnenforced = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_unenforced",
			Help: "Profiles that failed to compile with no previous version installed, so none of their rules are in effect.",
		},
		[]string{"namespace", "name"},
	)
)

func init() {
	metrics.Registry.MustRegister(profileCompileFailuresTotal, profileStale, profileUnenforced)
}

// profileScope maps a profile's namespace onto the bounded scope label.
// Cluster-scoped GlobalSecurityProfiles carry an empty namespace.
func profileScope(namespace string) string {
	if namespace == "" {
		return scopeGlobal
	}
	return scopeNamespaced
}
