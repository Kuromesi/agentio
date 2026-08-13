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

package securityprofile

import (
	"testing"

	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
	policysecurityprofile "istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
	"istio.io/istio/extensions/epe/pkg/wiring"
)

// Options configures the SecurityProfile-specific test harness.
type Options struct {
	// Filters overrides the production filter chain.
	Filters                []filter.Registration
	StreamLoggers          []filter.StreamLogger
	Kube                   kubernetes.Interface
	AuditRouter            *audit.Router
	CredentialClient       *credential.Client
	DisableResolutionProbe bool
	ObserveResponses       bool
}

// Harness adds a SecurityProfile fixture to the policy-neutral wire harness.
type Harness struct {
	*enginetest.Harness
	Fixture *Fixture
}

// New builds a SecurityProfile resolver and delegates wire processing to
// enginetest.
func New(t testing.TB, opts Options) *Harness {
	t.Helper()
	kube := opts.Kube
	if kube == nil {
		kube = k8sfake.NewClientset()
	}
	regs := opts.Filters
	if regs == nil {
		var err error
		regs, err = wiring.BuildFilters(wiring.Deps{
			Kube:             kube,
			CredentialClient: opts.CredentialClient,
		})
		if err != nil {
			t.Fatalf("securityprofile: BuildFilters: %v", err)
		}
	}

	fixture := NewFixture(t)
	var auditSink audit.Sink
	if opts.AuditRouter != nil {
		auditSink = opts.AuditRouter
	}
	core := enginetest.New(t, enginetest.Options{
		Resolve:                policysecurityprofile.NewResolver(fixture.Store, regs, auditSink),
		Registrations:          regs,
		StreamLoggers:          opts.StreamLoggers,
		DisableResolutionProbe: opts.DisableResolutionProbe,
		ObserveResponses:       opts.ObserveResponses,
	})
	return &Harness{Harness: core, Fixture: fixture}
}

// Store exposes the fixture's seedable profile store.
func (h *Harness) Store() *profilestore.FakeStore { return h.Fixture.Store }
