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
	"encoding/json"
	"errors"
	"net/netip"

	"google.golang.org/protobuf/encoding/protojson"

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

// PolicyHandler resolves the control plane's ordered inline SNI policies.
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

// Handle returns policies bound to the source; the native listener module evaluates the actual TLS SNI.
//
//nolint:gocyclo // Keep the CONNECT identity and Sandbox binding checks in one ordered flow.
func (h *PolicyHandler) Handle(ctx context.Context, request Request) (Result, error) {
	deny := Result{DenyStatus: envoytype.StatusCode_Forbidden}
	identity := request.Source.Workload
	fallback := identity.Name == "" || identity.Namespace == ""
	lookup := h.clusterID + "//Pod/" + identity.Namespace + "/" + identity.Name
	if fallback {
		ip, err := netip.ParseAddr(request.Source.PeerIP)
		if err != nil || request.Source.Principal == "" {
			return deny, nil
		}
		// Agentiod currently publishes Kubernetes IP aliases in the default network.
		lookup = "/" + ip.Unmap().String()
	}
	value, err := h.source.Demand(ctx, model.WorkloadType, lookup)
	if errors.Is(err, xdsclient.ErrNotFound) {
		return deny, nil
	}
	if err != nil {
		return Result{}, err
	}
	w := value.Value.(*workloadView)
	if fallback {
		if w.hostNetwork || w.principal != request.Source.Principal ||
			w.identity.Name == "" || w.identity.Namespace == "" ||
			(identity.Name != "" && identity.Name != w.identity.Name) ||
			(identity.Namespace != "" && identity.Namespace != w.identity.Namespace) {
			return deny, nil
		}
		identity = w.identity
	}
	uid := h.clusterID + "//Pod/" + identity.Namespace + "/" + identity.Name
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
	metadata := map[string]any{"workload": map[string]any{
		"name":      identity.Name,
		"namespace": identity.Namespace,
	}}
	if request.ConnectUDP {
		return Result{Metadata: metadata}, nil
	}
	policies = append(policies, w.policies...)
	combined := &extensions.SniTrafficPolicy{}
	for _, policy := range policies {
		combined.Rules = append(combined.Rules, policy.GetRules()...)
	}
	data, err := protojson.Marshal(combined)
	if err != nil {
		return Result{}, err
	}
	var policy map[string]any
	if err := json.Unmarshal(data, &policy); err != nil {
		return Result{}, err
	}
	metadata["sni"] = map[string]any{"policy": policy}
	return Result{Metadata: metadata}, nil
}
