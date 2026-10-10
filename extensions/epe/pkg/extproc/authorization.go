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
package extproc

import (
	"context"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
)

// requestContext shares one budget across rule evaluation and authorization.
func (s *Server) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.pluginBudget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.pluginBudget)
}

// authorize checks and pins the final target after all request headers run,
// before any request-body callback. It leaves the matching request and
// bypass response scope intact. Denials are local replies,
// so an authorization error cannot turn into an ext_proc transport fail-open.
func (s *Server) authorize(
	ctx context.Context,
	stream *filter.Stream,
	ops []filter.HeaderOp,
	route *filter.RouteMutation,
) (*filter.RouteMutation, *filter.Reply) {
	if s.authorizeRequest == nil {
		return route, nil
	}
	effective := *stream
	effective.Request = attributes.RequestAfterMutations(ctx, stream.Request, ops)
	if route != nil && route.Upstream != nil {
		effective.Upstream = route.Upstream
	}
	target, reply, err := s.authorizeRequest(ctx, &effective)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		log.FromContext(ctx).Error(err, "request authorization failed")
		return nil, &filter.Reply{Status: 500, Details: "epe_request_authorization_failed"}
	}
	if reply != nil {
		return nil, reply
	}
	if target == nil {
		return route, nil
	}
	result := filter.RouteMutation{Upstream: target}
	if route != nil {
		result.ClearCache = route.ClearCache
	}
	return &result, nil
}
