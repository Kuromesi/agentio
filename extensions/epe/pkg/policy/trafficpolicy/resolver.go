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
	"net/netip"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type resolver struct{ source Resources }

func (s *resolver) config(ctx context.Context, pod inputs.Pod) (egressauthz.Config, error) {
	snapshot, err := lookup(ctx, s.source, pod)
	if err != nil {
		return egressauthz.Config{}, err
	}
	return snapshot.entry.compiled.config, snapshot.entry.compiled.err
}

// NewAuthorizer loads immutable workload policies for aggregate authorization.
// It is independent of SecurityProfile resolution and bypass semantics.
func NewAuthorizer(source Resources) egressauthz.Authorizer {
	return &resolver{source: source}
}

func (s *resolver) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	peer := stream.Peer
	if !peer.Valid() {
		stream.Info.RecordAuthorization(filter.AuthorizationDecision{
			Action: "deny",
			Reason: filter.AuthorizationReasonMissingIdentity,
		})
		return nil, nil
	}
	cfg, err := s.config(ctx, inputs.Pod{
		Namespace: peer.Pod.Namespace,
		Name:      peer.Pod.Name,
		Labels:    peer.Labels,
	})
	if err != nil {
		return nil, err
	}
	return cfg.Authorize(ctx, stream, candidates)
}
