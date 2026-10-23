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

package xds

import (
	"container/list"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

// Each stream admits a small number of issuance requests. The issuer additionally
// enforces the process-wide signing limit and shares same-domain flights. Queued
// replay does not occupy goroutines; fresh requests go ahead of queued replay.
const sdsStreamConcurrency = 8

type sdsJob struct {
	name   string
	cancel context.CancelFunc
	queued *list.Element
}

type sdsCompletion struct {
	job     *sdsJob
	delta   GeneratedDelta
	err     error
	started time.Time
}

// Only the ADS loop owns jobs, pending, active and the watch. Workers return
// immutable completions and never write to the gRPC stream.
type sdsSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	generator *SDSGenerator
	scope     model.ClientScope
	jobs      map[string]*sdsJob
	pending   list.List
	active    int
	ready     chan sdsCompletion
}

func newSDSSession(ctx context.Context, generator *SDSGenerator, scope model.ClientScope) *sdsSession {
	ctx, cancel := context.WithCancel(ctx)
	return &sdsSession{
		ctx:       ctx,
		cancel:    cancel,
		generator: generator,
		scope:     scope,
		jobs:      make(map[string]*sdsJob),
		ready:     make(chan sdsCompletion, sdsStreamConcurrency),
	}
}

func (q *sdsSession) subscribe(names []string) {
	// Reverse insertion keeps the incoming request order ahead of earlier replay.
	for _, name := range slices.Backward(names) {
		if name == "*" {
			continue
		}
		if job := q.jobs[name]; job != nil {
			if job.queued != nil {
				q.pending.MoveToFront(job.queued)
			}
			continue
		}
		job := &sdsJob{name: name}
		job.queued = q.pending.PushFront(job)
		q.jobs[name] = job
	}
}

func (q *sdsSession) unsubscribe(names []string) {
	for _, name := range names {
		job := q.jobs[name]
		if job == nil {
			continue
		}
		delete(q.jobs, name)
		if job.queued != nil {
			q.pending.Remove(job.queued)
		}
		if job.cancel != nil {
			job.cancel()
		}
	}
}

func (q *sdsSession) start(snapshot model.ResourceSet) {
	for q.active < sdsStreamConcurrency && q.pending.Len() > 0 {
		element := q.pending.Front()
		job := element.Value.(*sdsJob)
		q.pending.Remove(element)
		job.queued = nil
		ctx, cancel := context.WithCancel(q.ctx)
		job.cancel = cancel
		q.active++
		go func() {
			defer cancel()
			started := time.Now()
			delta, err := q.generator.Generate(ctx, GenerationRequest{
				Scope:           q.scope,
				TypeURL:         model.SecretType,
				Snapshot:        snapshot,
				Full:            true,
				Subscription:    SubscriptionView{names: []string{job.name}},
				SubscribedNames: []string{job.name},
			})
			select {
			case q.ready <- sdsCompletion{job: job, delta: delta, err: err, started: started}:
			case <-q.ctx.Done():
			}
		}()
	}
}

func (s *Server) sendSDSCompletions(
	stream DeltaStream,
	connLog *agentlog.Logger,
	watch *watchState,
	first sdsCompletion,
) error {
	q := watch.sds
	batch := []sdsCompletion{first}
	// Send everything already ready, without waiting for any other certificate.
	for len(batch) < sdsStreamConcurrency {
		select {
		case next := <-q.ready:
			batch = append(batch, next)
		default:
			goto drained
		}
	}
drained:
	delta := GeneratedDelta{expiresAt: make(map[string]time.Time), versions: make(map[string]string)}
	for _, completion := range batch {
		q.active--
		job := completion.job
		// A late result from an unsubscribed or replaced request cannot remove or
		// overwrite the result of a new subscription for the same name.
		if q.jobs[job.name] != job {
			continue
		}
		delete(q.jobs, job.name)
		if completion.err != nil {
			return completion.err
		}
		if err := q.generator.provider.Authorize(q.scope); err != nil {
			delta.Removed = append(delta.Removed, job.name)
			delta.denied = append(delta.denied, generatedDenial{name: job.name, err: err})
			continue
		}
		if version, dynamic := completion.delta.versions[job.name]; dynamic {
			revision := q.generator.provider.SignerRevision()
			if revision == "" || !strings.HasPrefix(version, sdsVersionPrefix(revision)) ||
				!time.Now().Before(completion.delta.expiresAt[job.name]) {
				// State changed after issuance completed. Re-enter the issuer, which
				// returns the current generation or an explicit unavailable error.
				q.subscribe([]string{job.name})
				continue
			}
		}
		delta.Resources = append(delta.Resources, completion.delta.Resources...)
		delta.Removed = append(delta.Removed, completion.delta.Removed...)
		delta.denied = append(delta.denied, completion.delta.denied...)
		delta.allowed = append(delta.allowed, completion.delta.allowed...)
		maps.Copy(delta.expiresAt, completion.delta.expiresAt)
		maps.Copy(delta.versions, completion.delta.versions)
	}
	q.start(s.resources.Snapshot())
	return s.sendGeneratedDelta(stream, connLog, watch, GenerationRequest{
		Scope:    q.scope,
		TypeURL:  model.SecretType,
		Snapshot: s.resources.Snapshot(),
	}, delta, false, first.started)
}
