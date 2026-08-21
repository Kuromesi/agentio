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

package securityprofile

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
	"istio.io/istio/extensions/epe/pkg/wiring"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/yml"
)

const (
	kindSecurityProfile       = "SecurityProfile"
	kindGlobalSecurityProfile = "GlobalSecurityProfile"
	profileAPIVersion         = "agents.kruise.io/v1alpha1"
)

// defaultFixtureBase is the fixed epoch used for synthesized
// creationTimestamps; a fixed base keeps ordering tests reproducible.
var defaultFixtureBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Fixture seeds SecurityProfile / GlobalSecurityProfile objects into a
// FakeStore through the same admission semantics a real apiserver applies:
// CRD structural defaulting and offline validation (OpenAPI, list types,
// unknown-field pruning, CEL rules) run before the production compilation
// pipeline. Objects without a creationTimestamp receive deterministic
// timestamps that advance one second per applied object, mimicking
// "created earlier sorts earlier".
type Fixture struct {
	Store *profilestore.FakeStore

	t   testing.TB
	seq int
}

// NewFixture returns an empty fixture backed by a fresh FakeStore.
//
// Seeded profiles are projected against regs. Pass the registration set the
// resolver under test uses; with none, the fixture builds the default chain,
// which is what a test that only seeds and reads profiles wants.
//
// The default chain is built with a stop channel tied to the test's lifetime:
// BuildFilters starts the credential provider's certificate file watcher and
// its backstop ticker, and a nil stop channel would leave both running for the
// rest of the test binary. Harness.New passes its own regs, so this path is
// only for a fixture used on its own.
func NewFixture(t testing.TB, regs ...filter.Registration) *Fixture {
	t.Helper()
	if len(regs) == 0 {
		built, err := wiring.BuildFilters(wiring.Deps{Stop: test.NewStop(t)})
		if err != nil {
			t.Fatalf("securityprofile: BuildFilters: %v", err)
		}
		regs = built
	}
	return &Fixture{
		Store: profilestore.MakeFakeStore(regs...),
		t:     t,
	}
}

// ApplyYAML loads one or more profile documents ("---" separated) and seeds
// them into the store. Any admission-equivalent failure fails the test.
func (f *Fixture) ApplyYAML(yamlText string) *Fixture {
	f.t.Helper()
	for _, doc := range yml.SplitString(yamlText) {
		un, err := parseProfileDocument(doc)
		if err != nil {
			f.t.Fatalf("parse profile document: %v", err)
		}
		if err := f.applyUnstructured(un); err != nil {
			f.t.Fatalf("apply profile %s/%s: %v", un.GetNamespace(), un.GetName(), err)
		}
	}
	return f
}

// ValidateYAML runs each document through the same defaulting+validation
// pipeline as ApplyYAML but returns the first error instead of failing the
// test, and never touches the store. Use it to assert rejections.
func (f *Fixture) ValidateYAML(yamlText string) error {
	f.t.Helper()
	schemas, err := loadSchemas()
	if err != nil {
		f.t.Fatalf("load CRD schemas: %v", err)
	}
	for _, doc := range yml.SplitString(yamlText) {
		un, err := parseProfileDocument(doc)
		if err != nil {
			return err
		}
		if err := schemas.applyDefaults(un); err != nil {
			return err
		}
		if err := schemas.validate(un); err != nil {
			return err
		}
	}
	return nil
}

// ApplyProfile seeds a typed namespace-scoped profile through the same
// admission pipeline as YAML input.
func (f *Fixture) ApplyProfile(sp *v1alpha1.SecurityProfile) *Fixture {
	f.t.Helper()
	sp = sp.DeepCopy()
	sp.TypeMeta = metav1.TypeMeta{APIVersion: profileAPIVersion, Kind: kindSecurityProfile}
	un, err := toUnstructured(sp)
	if err != nil {
		f.t.Fatalf("convert SecurityProfile %s/%s: %v", sp.Namespace, sp.Name, err)
	}
	if err := f.applyUnstructured(un); err != nil {
		f.t.Fatalf("apply SecurityProfile %s/%s: %v", sp.Namespace, sp.Name, err)
	}
	return f
}

// ApplyGlobalProfile seeds a typed cluster-scoped profile through the same
// admission pipeline as YAML input.
func (f *Fixture) ApplyGlobalProfile(gsp *v1alpha1.GlobalSecurityProfile) *Fixture {
	f.t.Helper()
	gsp = gsp.DeepCopy()
	gsp.TypeMeta = metav1.TypeMeta{APIVersion: profileAPIVersion, Kind: kindGlobalSecurityProfile}
	un, err := toUnstructured(gsp)
	if err != nil {
		f.t.Fatalf("convert GlobalSecurityProfile %s: %v", gsp.Name, err)
	}
	if err := f.applyUnstructured(un); err != nil {
		f.t.Fatalf("apply GlobalSecurityProfile %s: %v", gsp.Name, err)
	}
	return f
}

func (f *Fixture) applyUnstructured(un *unstructured.Unstructured) error {
	schemas, err := loadSchemas()
	if err != nil {
		return fmt.Errorf("load CRD schemas: %w", err)
	}
	if err := schemas.applyDefaults(un); err != nil {
		return err
	}
	if err := schemas.validate(un); err != nil {
		return err
	}

	switch un.GetKind() {
	case kindSecurityProfile:
		sp := &v1alpha1.SecurityProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, sp); err != nil {
			return fmt.Errorf("convert to SecurityProfile: %w", err)
		}
		f.stampCreationTimestamp(&sp.ObjectMeta)
		f.Store.ProfileSet(sp)
	case kindGlobalSecurityProfile:
		gsp := &v1alpha1.GlobalSecurityProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, gsp); err != nil {
			return fmt.Errorf("convert to GlobalSecurityProfile: %w", err)
		}
		f.stampCreationTimestamp(&gsp.ObjectMeta)
		f.Store.GlobalProfileSet(gsp)
	default:
		return fmt.Errorf("unsupported kind %q", un.GetKind())
	}
	return nil
}

// stampCreationTimestamp assigns a deterministic timestamp when the object
// does not carry one. The step is one second because creationTimestamp has
// second precision on the wire; sub-second offsets would order in memory
// but not after serialization.
func (f *Fixture) stampCreationTimestamp(meta *metav1.ObjectMeta) {
	if !meta.CreationTimestamp.IsZero() {
		return
	}
	meta.CreationTimestamp = metav1.NewTime(defaultFixtureBase.Add(time.Duration(f.seq) * time.Second))
	f.seq++
}

func parseProfileDocument(doc string) (*unstructured.Unstructured, error) {
	un := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(doc), un); err != nil {
		return nil, fmt.Errorf("unmarshal document: %w", err)
	}
	if un.GetAPIVersion() != profileAPIVersion {
		return nil, fmt.Errorf("unsupported apiVersion %q, want %s", un.GetAPIVersion(), profileAPIVersion)
	}
	if kind := un.GetKind(); kind != kindSecurityProfile && kind != kindGlobalSecurityProfile {
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
	return un, nil
}

func toUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: content}, nil
}
