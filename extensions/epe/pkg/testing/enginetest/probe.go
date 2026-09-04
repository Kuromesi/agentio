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
	"sync"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit/accesslog"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// InfoProbe is appended to the harness's stream loggers to capture the
// authoritative StreamInfo of each stream: the matched units and the recorded
// error, neither of which appears on the wire.
//
// It is not how a test should read the audit outcome — Verdict.AccessLog is
// EPE's real output, and Verdict.outcome reads it. The probe does see
// Info.Outcome after derivation, because finishStream derives it before running
// the logger loop, so the few tests that assert Info.Outcome are reading the
// same derived value the accesslog carries.
type InfoProbe struct {
	mu      sync.Mutex
	infos   []*filter.StreamInfo
	streams []*filter.Stream
}

var _ filter.StreamLogger = (*InfoProbe)(nil)

// Log implements filter.StreamLogger.
func (p *InfoProbe) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infos = append(p.infos, info)
	p.streams = append(p.streams, st)
}

// Last returns the most recent StreamInfo, or nil when none was captured.
func (p *InfoProbe) Last() *filter.StreamInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.infos) == 0 {
		return nil
	}
	return p.infos[len(p.infos)-1]
}

// LastStream returns the most recent stream view, or nil.
func (p *InfoProbe) LastStream() *filter.Stream {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.streams) == 0 {
		return nil
	}
	return p.streams[len(p.streams)-1]
}

// Reset clears captured infos.
func (p *InfoProbe) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.infos = nil
	p.streams = nil
}

// CaptureAccessLogger is a synchronous accesslog.Logger that records every
// submitted entry, replacing the asynchronous production BufferedLogger so
// tests can assert entries deterministically.
type CaptureAccessLogger struct {
	mu      sync.Mutex
	entries []accesslog.Entry
}

var _ accesslog.Logger = (*CaptureAccessLogger)(nil)

func (c *CaptureAccessLogger) Submit(entry accesslog.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
}

// Entries returns a snapshot of all recorded entries.
func (c *CaptureAccessLogger) Entries() []accesslog.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]accesslog.Entry, len(c.entries))
	copy(out, c.entries)
	return out
}

// Reset clears recorded entries.
func (c *CaptureAccessLogger) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
}
