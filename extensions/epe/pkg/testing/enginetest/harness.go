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

package enginetest

import (
	"context"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	"istio.io/istio/extensions/epe/pkg/wiring"
)

// Options configures a Harness.
type Options struct {
	// Filters overrides the filter chain. Nil means the production chain
	// via wiring.BuildFilters with the fake kube client below.
	Filters []filter.Registration
	// StreamLoggers are extra statically registered stream loggers. The
	// policy-side audit logger is not one of them: the resolver derives it
	// per stream from the AuditRouter option.
	StreamLoggers []filter.StreamLogger
	// Kube backs Secret reads in token plugins. Nil means an empty fake
	// clientset.
	Kube kubernetes.Interface
	// AuditRouter routes audit events. Nil means events are discarded
	// (the resolver falls back to a no-op sink); register a recording sink
	// to observe them.
	AuditRouter *audit.Router
	// CredentialClient overrides the credential client used by internal
	// token plugins, pointing them at an in-process provider.
	CredentialClient *credential.Client
	// DisableResolutionProbe skips appending the info probe, for tests
	// that assert the exact logger composition.
	DisableResolutionProbe bool
	// ObserveResponses opens the response-headers phase via ModeOverride,
	// mirroring the production -observe-responses flag.
	ObserveResponses bool
}

// Harness wires the real extproc.Server with a seedable profile store and
// capturing observability, mirroring the production assembly in
// server.New minus the gRPC transport.
type Harness struct {
	Server    *extproc.Server
	Fixture   *Fixture
	AccessLog *CaptureAccessLogger

	probe *InfoProbe
}

// New builds a Harness. Run resolves the profiles seeded through h.Fixture.
func New(t testing.TB, opts Options) *Harness {
	t.Helper()

	kube := opts.Kube
	if kube == nil {
		kube = k8sfake.NewClientset()
	}
	deps := wiring.Deps{
		Kube:             kube,
		CredentialClient: opts.CredentialClient,
	}
	regs := opts.Filters
	if regs == nil {
		var err error
		regs, err = wiring.BuildFilters(deps)
		if err != nil {
			t.Fatalf("enginetest: BuildFilters: %v", err)
		}
	}
	loggers := opts.StreamLoggers

	h := &Harness{
		Fixture:   NewFixture(t),
		AccessLog: &CaptureAccessLogger{},
	}
	if !opts.DisableResolutionProbe {
		h.probe = &InfoProbe{}
		loggers = append(append([]filter.StreamLogger{}, loggers...), h.probe)
	}
	// Converting a nil *audit.Router straight to audit.Sink would produce a
	// non-nil interface holding a nil pointer, which panics on Enqueue rather
	// than falling back to the no-op sink.
	var auditSink audit.Sink
	if opts.AuditRouter != nil {
		auditSink = opts.AuditRouter
	}
	h.Server = extproc.NewServer(extproc.ServerDeps{
		Resolve:          securityprofile.NewResolver(h.Fixture.Store, regs, auditSink),
		Registrations:    regs,
		StreamLoggers:    loggers,
		AuditLogger:      h.AccessLog,
		ObserveResponses: opts.ObserveResponses,
	})
	return h
}

// Probe exposes the harness's info probe (nil when disabled).
func (h *Harness) Probe() *InfoProbe { return h.probe }

// Store exposes the seedable profile store.
func (h *Harness) Store() *profilestore.FakeStore { return h.Fixture.Store }

// Run drives one request through the real Process loop and reduces the
// response sequence to a Verdict. Process errors land in Verdict.Err.
func (h *Harness) Run(t testing.TB, rb *RequestBuilder) *Verdict {
	t.Helper()
	return h.RunMessages(t, rb.Build())
}

// RunMessages is the escape hatch for hand-crafted message sequences.
func (h *Harness) RunMessages(t testing.TB, msgs []*extProcPb.ProcessingRequest) *Verdict {
	t.Helper()

	if h.probe != nil {
		h.probe.Reset()
	}
	stream := NewScriptedStream(context.Background(), msgs...)
	err := h.Server.Process(stream)
	verdict := ParseVerdict(stream.Responses(), err)
	if h.probe != nil {
		verdict.Info = h.probe.Last()
	}
	verdict.AccessLog = h.AccessLog.Entries()
	return verdict
}

// RunStream runs Process against a caller-owned stream, for interactive or
// fault-injection scenarios.
func (h *Harness) RunStream(_ testing.TB, stream extProcPb.ExternalProcessor_ProcessServer) error {
	return h.Server.Process(stream)
}
