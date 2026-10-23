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

package egressauthz

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/pkg/dns"
)

// ConfigResolver optionally supplies workload policies for the current request.
type ConfigResolver func(context.Context, *filter.Stream) (Config, error)

// NewAuthorizer snapshots global restrictions and optional workload policies,
// then resolves, authorizes, and pins the destination in one pass.
// global must return a validated immutable snapshot; policies may be nil.
func NewAuthorizer(client *dns.Client, global func() Config, policies ConfigResolver) engine.RequestAuthorizer {
	return func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
		cfg := global()
		if policies != nil {
			workload, err := policies(ctx, stream)
			if err != nil {
				stream.Info.RecordAuthorization(filter.AuthorizationDecision{
					Action: "error",
					Reason: filter.AuthorizationReasonPolicyLoadFailed,
				})
				return nil, nil, err
			}
			cfg.Policies = workload.Policies
			cfg.Family = workload.Family
		}
		return Authorize(ctx, cfg, client, stream)
	}
}
