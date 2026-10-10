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

package trafficpolicy

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/pkg/dns"
)

type resolver struct{ source Resources }

func (s *resolver) config(ctx context.Context, pod inputs.Pod) (egressauthz.Config, error) {
	snapshot, err := lookup(ctx, s.source, pod)
	if err != nil {
		return egressauthz.Config{}, err
	}
	return snapshot.entry.compiled.config, snapshot.entry.compiled.err
}

// NewAuthorizer loads the workload's policies when request rules have completed.
// It is independent of SecurityProfile resolution and bypass semantics.
func NewAuthorizer(source Resources, client *dns.Client) engine.RequestAuthorizer {
	s := &resolver{source: source}
	return func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
		peer := stream.Peer
		cfg, err := s.config(ctx, inputs.Pod{
			Namespace: peer.Pod.Namespace,
			Name:      peer.Pod.Name,
			Labels:    peer.Labels,
		})
		if err != nil {
			return nil, nil, err
		}
		return egressauthz.Authorize(ctx, cfg, client, stream)
	}
}
