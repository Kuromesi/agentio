// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"testing"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/util/sets"
)

func TestWorkloadConfigNeedsPush(t *testing.T) {
	dedicated := &model.Proxy{
		ID:       "worker-0.substrate-system",
		Metadata: &model.NodeMetadata{Namespace: "substrate-system"},
		Labels:   map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}
	regular := &model.Proxy{
		ID:       dedicated.ID,
		Metadata: dedicated.Metadata,
		Labels:   map[string]string{},
	}

	tests := []struct {
		name  string
		proxy *model.Proxy
		req   *model.PushRequest
		want  bool
	}{
		{
			name:  "own Worker workload changed",
			proxy: dedicated,
			req: &model.PushRequest{
				AddressesUpdated: sets.New("//Pod/substrate-system/worker-0"),
			},
			want: true,
		},
		{
			name:  "another workload changed",
			proxy: dedicated,
			req: &model.PushRequest{
				AddressesUpdated: sets.New("//Pod/substrate-system/worker-1"),
			},
			want: false,
		},
		{
			name:  "regular ztunnel own workload changed",
			proxy: regular,
			req: &model.PushRequest{
				AddressesUpdated: sets.New("//Pod/substrate-system/worker-0"),
			},
			want: false,
		},
		{
			name:  "empty update",
			proxy: dedicated,
			req:   &model.PushRequest{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := workloadConfigNeedsPush(tt.proxy, tt.req); got != tt.want {
				t.Fatalf("workloadConfigNeedsPush() = %v, want %v", got, tt.want)
			}
		})
	}
}
