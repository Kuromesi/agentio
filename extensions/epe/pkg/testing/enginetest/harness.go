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

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc"
)

// Options configures a Harness.
type Options struct {
	// Resolve supplies the policy-neutral units for each request. Required.
	Resolve engine.Resolver
	// Registrations is the action order used to evaluate resolved units.
	Registrations []filter.Registration
	// StreamLoggers are extra statically registered stream loggers. The
	// resolver may also return one policy-owned logger per stream.
	StreamLoggers []filter.StreamLogger
	// DisableResolutionProbe skips appending the info probe, for tests
	// that assert the exact logger composition.
	DisableResolutionProbe bool
}

// Harness wires the real extproc.Server to a caller-supplied resolver and
// captures observability, mirroring the policy-neutral part of production
// assembly without the gRPC transport.
type Harness struct {
	Server    *extproc.Server
	AccessLog *CaptureAccessLogger

	probe *InfoProbe
}

// New builds a policy-neutral Harness around the supplied resolver.
func New(t testing.TB, opts Options) *Harness {
	t.Helper()
	if opts.Resolve == nil {
		t.Fatal("enginetest: Resolve is required")
	}
	loggers := opts.StreamLoggers

	h := &Harness{
		AccessLog: &CaptureAccessLogger{},
	}
	if !opts.DisableResolutionProbe {
		h.probe = &InfoProbe{}
		loggers = append(append([]filter.StreamLogger{}, loggers...), h.probe)
	}
	h.Server = extproc.NewServer(extproc.ServerDeps{
		Resolve:       opts.Resolve,
		Registrations: opts.Registrations,
		StreamLoggers: loggers,
		AuditLogger:   h.AccessLog,
	})
	return h
}

// Probe exposes the harness's info probe (nil when disabled).
func (h *Harness) Probe() *InfoProbe { return h.probe }

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
	// Both observability sinks are scoped to this run, so a test asserting the
	// second request's outcome cannot read the first request's entry.
	h.AccessLog.Reset()
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
