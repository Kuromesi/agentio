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

// Package runnable provides the minimal long-running component contract for
// the EPE binary: a plain context-driven group runner plus
// adapters for gRPC/HTTP servers.
package runnable

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Runnable is a long-running component. Start blocks until ctx is cancelled
// or the component fails.
type Runnable interface {
	Start(ctx context.Context) error
}

// Func adapts a plain function to the Runnable interface.
type Func func(ctx context.Context) error

// Start implements Runnable.
func (f Func) Start(ctx context.Context) error { return f(ctx) }

// Group runs a set of Runnables together: all are started concurrently, the
// first failure cancels the rest, and Start returns once every member has
// stopped.
type Group struct {
	members []Runnable
}

// Add appends members to the group. Not safe for use after Start.
func (g *Group) Add(r ...Runnable) {
	g.members = append(g.members, r...)
}

// Start runs all members and blocks until they have all stopped. The
// returned error is the first member failure, if any.
func (g *Group) Start(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, m := range g.members {
		eg.Go(func() error { return m.Start(ctx) })
	}
	return eg.Wait()
}
