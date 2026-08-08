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
package profilestore

import (
	"errors"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/extensions/epe/pkg/metrics"
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
)

// invalidItem builds the identity-bearing CompileError item the collection
// transform produces for a source object that failed to compile. It takes the
// object and spec separately so both CRD scopes can use it: the namespaced
// newTestProfile and the cluster-scoped newTestGlobalProfile.
func invalidItem(obj metav1.Object, spec *v1alpha1.SecurityProfileSpec) *securityprofile.Profile {
	return securityprofile.InvalidProfile(obj, spec, errors.New("invalid selector"))
}

// invalidNamespaced is the namespaced shorthand used by most tests here.
func invalidNamespaced(name, namespace string) *securityprofile.Profile {
	obj := newTestProfile(name, namespace, map[string]string{"app": "x"})
	return invalidItem(obj, &obj.Spec)
}

func TestApplyBatch_CountsRejectedNamespacedVersion(t *testing.T) {
	s := NewStore()
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced))

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("p", "default"), Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced)) - before; got != 1 {
		t.Fatalf("compile failures delta for scope %q = %v, want 1", scopeNamespaced, got)
	}
}

// The cluster-scoped CRD is a distinct Go type whose namespace is always empty,
// which is what selects the global label. Use the real type rather than a
// namespaced profile with a blank namespace.
func TestApplyBatch_CountsRejectedGlobalVersion(t *testing.T) {
	s := NewStore()
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeGlobal))

	g := newTestGlobalProfile("g", map[string]string{"app": "x"})
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidItem(g, &g.Spec), Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeGlobal)) - before; got != 1 {
		t.Fatalf("compile failures delta for scope %q = %v, want 1", scopeGlobal, got)
	}
}

func TestApplyBatch_ValidItemCountsNothing(t *testing.T) {
	s := NewStore()
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced))

	good := newTestProfile("p", "default", map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(good, &good.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiled, Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced)) - before; got != 0 {
		t.Fatalf("compile failures delta = %v, want 0 for a valid profile", got)
	}
}

// staleValue reports the gauge for one identity and whether the series exists.
func staleValue(t testing.TB, namespace, name string) (float64, bool) {
	t.Helper()
	return gaugeValue(t, "epe_profile_stale", namespace, name)
}

// unenforcedValue reports the gauge marking identities with nothing installed.
func unenforcedValue(t testing.TB, namespace, name string) (float64, bool) {
	t.Helper()
	return gaugeValue(t, "epe_profile_unenforced", namespace, name)
}

func gaugeValue(t testing.TB, metricName, namespace, name string) (float64, bool) {
	t.Helper()
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != metricName {
			continue
		}
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			if got["namespace"] == namespace && got["name"] == name {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func installGood(t testing.TB, s *store, name, namespace string) *securityprofile.Profile {
	t.Helper()
	obj := newTestProfile(name, namespace, map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiled, Event: controllers.EventAdd},
	})
	return compiled
}

func TestApplyBatch_InvalidUpdateMarksProfileStale(t *testing.T) {
	s := NewStore()
	good := installGood(t, s, "stale-me", "default")

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("stale-me", "default"), Event: controllers.EventUpdate},
	})

	v, ok := staleValue(t, "default", "stale-me")
	if !ok || v != 1 {
		t.Fatalf("stale gauge = (%v, exists=%v), want (1, true)", v, ok)
	}
}

func TestApplyBatch_ValidVersionClearsStale(t *testing.T) {
	s := NewStore()
	good := installGood(t, s, "recover-me", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("recover-me", "default"), Event: controllers.EventUpdate},
	})
	if _, ok := staleValue(t, "default", "recover-me"); !ok {
		t.Fatal("precondition: profile should be marked stale")
	}

	installGood(t, s, "recover-me", "default")

	if _, ok := staleValue(t, "default", "recover-me"); ok {
		t.Fatal("stale series still present after a valid version landed; absence must mean healthy")
	}
}

func TestApplyBatch_DeleteClearsStale(t *testing.T) {
	s := NewStore()
	good := installGood(t, s, "delete-me", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("delete-me", "default"), Event: controllers.EventUpdate},
	})
	if _, ok := staleValue(t, "default", "delete-me"); !ok {
		t.Fatal("precondition: profile should be marked stale")
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, Event: controllers.EventDelete},
	})

	if _, ok := staleValue(t, "default", "delete-me"); ok {
		t.Fatal("stale series leaked after the profile was deleted")
	}
}

func TestApplyBatch_RejectedWithNoPriorVersionIsNotStale(t *testing.T) {
	s := NewStore()

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("never-installed", "default"), Event: controllers.EventAdd},
	})

	if _, ok := staleValue(t, "default", "never-installed"); ok {
		t.Fatal("nothing is being served for this identity, so it is absent, not stale")
	}
}

// The dangerous case: a profile whose first published version was rejected.
// Nothing is installed, so no rule of it is enforced — the pods it targets are
// unprotected. `stale` deliberately stays absent here (nothing is being
// served), and the compile counter carries no identity, so without this gauge
// the operator cannot tell WHICH profile is unenforced, only that some
// rejection happened somewhere.
func TestApplyBatch_RejectedWithNoPriorVersionIsUnenforced(t *testing.T) {
	s := NewStore()

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("never-installed", "default"), Event: controllers.EventAdd},
	})

	v, ok := unenforcedValue(t, "default", "never-installed")
	if !ok || v != 1 {
		t.Fatalf("unenforced gauge = (%v, exists=%v), want (1, true)", v, ok)
	}
}

// A rejected update over an installed version is stale, not unenforced: the
// previous version keeps enforcing. Conflating the two would page someone at
// 3am for a profile that is still protecting its pods.
func TestApplyBatch_StaleProfileIsNotUnenforced(t *testing.T) {
	s := NewStore()
	good := installGood(t, s, "still-serving", "default")

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("still-serving", "default"), Event: controllers.EventUpdate},
	})

	if _, ok := unenforcedValue(t, "default", "still-serving"); ok {
		t.Fatal("an installed previous version is still enforcing; this is stale, not unenforced")
	}
}

func TestApplyBatch_ValidVersionClearsUnenforced(t *testing.T) {
	s := NewStore()
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("recovers", "default"), Event: controllers.EventAdd},
	})
	if _, ok := unenforcedValue(t, "default", "recovers"); !ok {
		t.Fatal("precondition: profile should be marked unenforced")
	}

	installGood(t, s, "recovers", "default")

	if _, ok := unenforcedValue(t, "default", "recovers"); ok {
		t.Fatal("unenforced series still present after a valid version landed")
	}
}

func TestApplyBatch_DeleteClearsUnenforced(t *testing.T) {
	s := NewStore()
	bad := invalidNamespaced("delete-unenforced", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: bad, Event: controllers.EventAdd},
	})
	if _, ok := unenforcedValue(t, "default", "delete-unenforced"); !ok {
		t.Fatal("precondition: profile should be marked unenforced")
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: bad, Event: controllers.EventDelete},
	})

	if _, ok := unenforcedValue(t, "default", "delete-unenforced"); ok {
		t.Fatal("unenforced series leaked after the profile was deleted")
	}
}
