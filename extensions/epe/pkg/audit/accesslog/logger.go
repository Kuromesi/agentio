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
// Package accesslog provides a non-blocking INFO-level audit logger for the
// EPE data plane. Every successfully handled ext-proc
// RequestHeaders call produces exactly one Entry summarising which
// SecurityProfile rules fired and what the final outcome was.
//
// The default Logger buffers entries through an in-memory channel consumed
// by a single worker goroutine, so request-path latency only pays for a
// non-blocking channel send. When the buffer is full Submit drops the
// entry and increments a Prometheus counter rather than blocking the
// caller.
package accesslog

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/audit"
)

// DefaultBufferSize is the channel capacity used when the caller does not
// configure --audit-log-buffer-size.
const DefaultBufferSize = 4096

// Entry is the per-request audit payload assembled by the request handler.
//
// Outcome takes one of: "passthrough", "mutated", "blocked", "bypassed",
// "error". Actions records every filter that materially acted on the
// request in the form "<filter>:<ns>/<profile>/<rule>#<ordinal>" (the
// UnitID string). Skipped counts filters that failed open or asked for a body
// that never resolved. Units counts matched policy units (rules), not profiles.
type Entry struct {
	RequestID string
	Pod       types.NamespacedName
	Method    string
	Host      string
	Path      string
	Units     int
	Outcome   string
	Actions   []string
	Skipped   map[string]int
	Error     string
}

// Logger is the contract the request handler invokes once per request via
// a deferred call. Implementations MUST be safe for concurrent use and
// MUST NOT block the caller.
type Logger interface {
	Submit(entry Entry)
}

// Nop returns a Logger whose Submit is a no-op. Used as a default when the
// handler is constructed without an audit logger (e.g. unit tests) so the
// dispatch path can call Submit unconditionally.
func Nop() Logger { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Submit(Entry) {}

// BufferedLogger is the default Logger implementation. Submit performs a
// non-blocking channel send; a single worker goroutine started by Start
// consumes the channel and writes one logr Info record per entry.
//
// BufferedLogger satisfies the runnable.Runnable contract so it can be
// wired into the runnable group alongside the ext-proc server.
type BufferedLogger struct {
	logger logr.Logger
	d      *audit.Dispatcher[Entry]
}

// NewBufferedLogger constructs a BufferedLogger backed by the given
// logr.Logger and channel capacity. bufferSize <= 0 falls back to
// DefaultBufferSize.
func NewBufferedLogger(logger logr.Logger, bufferSize int) *BufferedLogger {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	l := &BufferedLogger{logger: logger}
	// The dispatcher flushes buffered entries on ctx cancellation without
	// closing the channel, so a late Submit remains safe.
	l.d = audit.NewDispatcher("accesslog", bufferSize, 1,
		func(_ context.Context, e Entry) { l.emit(e) },
		func(audit.DropReason) { AuditLogDroppedTotal.Inc() })
	return l
}

// Submit enqueues entry for asynchronous emission. The call is
// non-blocking: when the buffer is full the entry is dropped and
// AuditLogDroppedTotal is incremented. A nil receiver is a no-op so
// uninitialised Loggers do not panic from inside the request path.
func (l *BufferedLogger) Submit(entry Entry) {
	if l == nil {
		return
	}
	l.d.Enqueue(entry)
}

// Start drains the entry channel until ctx is cancelled, then flushes any
// remaining entries and returns. It implements runnable.Runnable.
func (l *BufferedLogger) Start(ctx context.Context) error {
	return l.d.Start(ctx)
}

// emit converts an Entry into structured key-value pairs and writes one
// logr Info record. Error is only emitted when non-empty to keep the
// happy-path line short.
func (l *BufferedLogger) emit(e Entry) {
	kvs := []any{
		"requestID", e.RequestID,
		"pod", e.Pod.String(),
		"method", e.Method,
		"host", e.Host,
		"path", e.Path,
		"units", e.Units,
		"outcome", e.Outcome,
		"actions", e.Actions,
		"skipped", e.Skipped,
	}
	if e.Error != "" {
		kvs = append(kvs, "error", e.Error)
	}
	l.logger.Info("egress request handled", kvs...)
}
