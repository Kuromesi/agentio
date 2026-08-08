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
package audit

// Sink is the extension point for audit event delivery. The audit stream
// logger pushes every matching Event to the Router, which forwards it to
// the Sink registered for the event's Kind.
//
// Enqueue must be non-blocking and safe for concurrent use.
type Sink interface {
	Enqueue(Event)
}

// NopSink returns a Sink that silently discards every Event.
func NopSink() Sink { return nopSink{} }

type nopSink struct{}

func (nopSink) Enqueue(Event) {}

// Router dispatches each Event to the Sink registered for its
// Audit.Kind.
type Router struct {
	sinks map[string]Sink
}

// NewRouter returns an empty Router. Register sinks before use.
func NewRouter() *Router {
	return &Router{sinks: make(map[string]Sink)}
}

// Register binds a Sink to a sink kind.
func (r *Router) Register(kind string, s Sink) {
	r.sinks[kind] = s
}

// Enqueue routes the event to the sink registered for its Kind.
func (r *Router) Enqueue(e Event) {
	if e.Audit == nil {
		EvalDroppedTotal.WithLabelValues("no_sink").Inc()
		return
	}
	s, ok := r.sinks[e.Audit.Kind]
	if !ok {
		EvalDroppedTotal.WithLabelValues("no_sink").Inc()
		return
	}
	s.Enqueue(e)
}
