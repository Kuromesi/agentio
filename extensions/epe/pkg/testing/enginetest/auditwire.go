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
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/audit/sinks/webhook"
)

// AuditMode selects how webhook deliveries execute.
type AuditMode int

const (
	// AuditSync delivers each webhook inline on the request goroutine,
	// through the same dispatch code the worker pool runs. Deliveries are
	// complete when Harness.Run returns, so absence assertions need no
	// barrier. Default.
	AuditSync AuditMode = iota
	// AuditBuffered uses the production asynchronous dispatcher with a
	// real worker pool.
	AuditBuffered
)

// AuditOptions configures WireAudit.
type AuditOptions struct {
	Mode AuditMode
	// BufferSize and Workers apply to AuditBuffered; zero means small
	// test-friendly defaults (64 / 1).
	BufferSize  int
	Workers     int
	InsecureTLS bool
}

// AuditWiring replicates the production audit wiring — Buffered dispatcher,
// webhook Sink, Router registration — with a mode switch for synchronous
// delivery. Pass Router to Options.AuditRouter when building the Harness.
type AuditWiring struct {
	Router *audit.Router

	mode     AuditMode
	buffered *webhook.Buffered
}

// Drain blocks until every accepted delivery has completed. It is a no-op
// in AuditSync mode, where deliveries finish before Harness.Run returns.
// Call it before absence assertions in AuditBuffered mode.
func (w *AuditWiring) Drain(t testing.TB) {
	t.Helper()
	if w.mode == AuditSync {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.buffered.Drain(ctx); err != nil {
		t.Fatalf("drain audit dispatcher: %v", err)
	}
}

type syncDispatcher struct {
	buffered *webhook.Buffered
}

func (s syncDispatcher) Enqueue(evt webhook.Delivery) {
	s.buffered.DispatchNow(context.Background(), evt)
}

// WireAudit assembles the audit delivery pipeline, mirroring the traffic
// extension main wiring. In AuditBuffered mode the worker pool is started
// and drained on test cleanup.
func WireAudit(t testing.TB, opts AuditOptions) *AuditWiring {
	t.Helper()

	bufferSize := opts.BufferSize
	if bufferSize <= 0 {
		bufferSize = 64
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 1
	}
	logger := ctrllog.Log.WithName("enginetest-audit")
	buffered := webhook.NewBuffered(logger, bufferSize, workers, opts.InsecureTLS)

	var dispatcher webhook.Dispatcher
	switch opts.Mode {
	case AuditSync:
		dispatcher = syncDispatcher{buffered: buffered}
	case AuditBuffered:
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := buffered.Start(ctx); err != nil && ctx.Err() == nil {
				t.Errorf("audit dispatcher exited: %v", err)
			}
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		dispatcher = buffered
	}

	router := audit.NewRouter()
	router.Register(audit.SinkKindWebhook, webhook.NewSink(dispatcher, logger))
	return &AuditWiring{Router: router, mode: opts.Mode, buffered: buffered}
}
