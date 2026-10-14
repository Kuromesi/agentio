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

package processor

import (
	"context"
	"errors"
	"strings"

	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// DemandSource is satisfied by the shared Delta ADS client. Named subscriptions
// stay live until deletion, so decisions observe updates without polling.
type DemandSource interface {
	Demand(context.Context, string, string) (*xdsclient.Resource, error)
}

// PolicyHandler evaluates the control plane's precompiled inline SNI projection.
// The Pod UID follows Agentio's Kubernetes Workload naming convention. A Sandbox
// must still be hosted by that Workload before its owned policy is considered.
type PolicyHandler struct {
	source    DemandSource
	clusterID string
}

// NewPolicyHandler creates a CONNECT policy handler with explicit dependencies.
func NewPolicyHandler(source DemandSource, clusterID string) *PolicyHandler {
	return &PolicyHandler{source: source, clusterID: clusterID}
}

// Handle evaluates the policies bound to the request's source identity.
func (h *PolicyHandler) Handle(ctx context.Context, request Request) (Result, error) {
	if request.Headers.SNI == "" {
		return Result{}, nil
	}
	deny := Result{DenyStatus: envoytype.StatusCode_Forbidden}
	if request.Source.Workload.Name == "" || request.Source.Workload.Namespace == "" {
		return deny, nil
	}
	uid := h.clusterID + "//Pod/" + request.Source.Workload.Namespace + "/" + request.Source.Workload.Name
	value, err := h.source.Demand(ctx, model.WorkloadType, uid)
	if errors.Is(err, xdsclient.ErrNotFound) {
		return deny, nil
	}
	if err != nil {
		return Result{}, err
	}
	w := value.Value.(*workloadView)
	if w.uid != uid {
		return deny, nil
	}
	var policies []*extensions.SniTrafficPolicy
	if request.Source.SandboxID != "" {
		value, err := h.source.Demand(ctx, model.SandboxType, request.Source.SandboxID)
		if errors.Is(err, xdsclient.ErrNotFound) {
			return deny, nil
		}
		if err != nil {
			return Result{}, err
		}
		s := value.Value.(*sandboxView)
		if s.uid != request.Source.SandboxID || s.workloadUID != uid {
			return deny, nil
		}
		policies = append(policies, s.policies...)
	}
	policies = append(policies, w.policies...)
	return evaluateSNI(policies, request.Headers.SNI), nil
}

func evaluateSNI(policies []*extensions.SniTrafficPolicy, sni string) Result {
	action := "passthrough"
	for _, policy := range policies {
		for _, rule := range policy.GetRules() {
			if !matches(rule.GetMatch().GetSni(), sni) {
				continue
			}
			switch rule.GetAction() {
			case extensions.SniAction_SNI_ACTION_TLS_TERMINATION:
				action = "terminate"
			case extensions.SniAction_SNI_ACTION_PASSTHROUGH:
				action = "passthrough"
			case extensions.SniAction_SNI_ACTION_DENY:
				return Result{DenyStatus: envoytype.StatusCode_Forbidden}
			}
			return tlsResult(action)
		}
	}
	return tlsResult(action)
}

func tlsResult(action string) Result {
	return Result{Metadata: map[string]any{"tls": map[string]any{"action": action}}}
}

func matches(patterns []string, sni string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == sni {
			return true
		}
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(sni, pattern[1:]) {
			return true
		}
	}
	return false
}
