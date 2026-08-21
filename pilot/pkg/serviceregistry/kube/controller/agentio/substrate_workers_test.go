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

package agentio

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/substrateapi"
)

type fakeListWorkersClient struct {
	responses map[string]*substrateapi.ListWorkersResponse
	err       error
	requests  []*substrateapi.ListWorkersRequest
}

func (f *fakeListWorkersClient) ListWorkers(
	_ context.Context,
	req *substrateapi.ListWorkersRequest,
	_ ...grpc.CallOption,
) (*substrateapi.ListWorkersResponse, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	return f.responses[req.GetPageToken()], nil
}

func TestSubstrateWorkerSourceBuildsActorContextFromAllPages(t *testing.T) {
	client := &fakeListWorkersClient{responses: map[string]*substrateapi.ListWorkersResponse{
		"": {
			Workers:       []*substrateapi.Worker{assignedWorker("worker-a", "pod-uid-a", 9)},
			NextPageToken: "page-2",
		},
		"page-2": {
			Workers: []*substrateapi.Worker{{
				Metadata:        &substrateapi.ResourceMetadata{Version: 4},
				WorkerNamespace: "workers",
				WorkerPool:      "pool-b",
				WorkerPod:       "worker-b",
				WorkerPodUid:    "pod-uid-b",
				Status:          &substrateapi.WorkerStatus{},
			}},
		},
	}}
	changes := 0
	source := newSubstrateWorkerSourceForClient(client, substrateWorkerConfig{
		PageSize:   1,
		RPCTimeout: time.Second,
	}, func() { changes++ })

	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("refresh() failed: %v", err)
	}
	if len(client.requests) != 2 || client.requests[0].GetPageSize() != 1 || client.requests[1].GetPageToken() != "page-2" {
		t.Fatalf("ListWorkers requests = %+v, want two paginated requests", client.requests)
	}
	if changes != 1 {
		t.Fatalf("change notifications = %d, want 1", changes)
	}

	actor := source.actorContextForWorker("workers", "worker-a", "pod-uid-a")
	if actor == nil {
		t.Fatal("actorContextForWorker() returned nil for assigned worker")
	}
	if actor.GetActorUid() != "actor-uid-a" || actor.GetActorName() != "actor-a" || actor.GetAtespace() != "tenant-a" || actor.GetGeneration() != 9 {
		t.Fatalf("ActorContext = %+v, want actor-a generation 9", actor)
	}
	wantLabels := map[string]string{
		ActorIdentityLabelUID:               "actor-uid-a",
		ActorIdentityLabelName:              "actor-a",
		ActorIdentityLabelAtespace:          "tenant-a",
		ActorIdentityLabelGeneration:        "9",
		ActorIdentityLabelTemplateNamespace: "templates",
		ActorIdentityLabelTemplateName:      "python-agent",
		ActorIdentityLabelWorkerPool:        "pool-a",
	}
	for key, want := range wantLabels {
		if got := actor.GetLabels()[key]; got != want {
			t.Fatalf("ActorContext label %q = %q, want %q", key, got, want)
		}
	}
	if got := source.actorContextForWorker("workers", "worker-a", "recreated-pod-uid"); got != nil {
		t.Fatalf("actorContextForWorker() with mismatched Pod UID = %+v, want nil", got)
	}
	if got := source.actorContextForWorker("workers", "worker-b", "pod-uid-b"); got != nil {
		t.Fatalf("actorContextForWorker() for unassigned worker = %+v, want nil", got)
	}
}

func TestSubstrateWorkerSourcePublishesOnlySuccessfulChanges(t *testing.T) {
	client := &fakeListWorkersClient{responses: map[string]*substrateapi.ListWorkersResponse{
		"": {Workers: []*substrateapi.Worker{assignedWorker("worker-a", "pod-uid-a", 9)}},
	}}
	changes := 0
	source := newSubstrateWorkerSourceForClient(client, substrateWorkerConfig{
		PageSize:   1000,
		RPCTimeout: time.Second,
	}, func() { changes++ })

	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("first refresh() failed: %v", err)
	}
	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("unchanged refresh() failed: %v", err)
	}
	if changes != 1 {
		t.Fatalf("change notifications after identical snapshot = %d, want 1", changes)
	}

	client.err = errors.New("ateapi unavailable")
	if err := source.refresh(context.Background()); err == nil {
		t.Fatal("refresh() succeeded while ListWorkers failed")
	}
	if got := source.actorContextForWorker("workers", "worker-a", "pod-uid-a"); got == nil {
		t.Fatal("failed refresh discarded the last successful Actor binding")
	}
	if changes != 1 {
		t.Fatalf("change notifications after failed refresh = %d, want 1", changes)
	}

	client.err = nil
	client.responses[""] = &substrateapi.ListWorkersResponse{Workers: []*substrateapi.Worker{{
		Metadata:        &substrateapi.ResourceMetadata{Version: 10},
		WorkerNamespace: "workers",
		WorkerPod:       "worker-a",
		WorkerPodUid:    "pod-uid-a",
		Status:          &substrateapi.WorkerStatus{},
	}}}
	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("unassigned refresh() failed: %v", err)
	}
	if got := source.actorContextForWorker("workers", "worker-a", "pod-uid-a"); got != nil {
		t.Fatalf("removed Actor binding remained: %+v", got)
	}
	if changes != 2 {
		t.Fatalf("change notifications after removal = %d, want 2", changes)
	}
}

func TestSubstrateWorkerConfigRejectsIncompleteMTLS(t *testing.T) {
	base := substrateWorkerConfig{
		Address:                "api.ate-system.svc:443",
		ServerName:             "api.ate-system.svc",
		CAFile:                 "/run/substrate/trust-bundle.pem",
		ClientCredentialBundle: "/run/substrate/credential-bundle.pem",
		PollInterval:           2 * time.Second,
		RPCTimeout:             time.Second,
		PageSize:               1000,
	}
	if err := base.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*substrateWorkerConfig)
	}{
		{name: "missing server name", mutate: func(c *substrateWorkerConfig) { c.ServerName = "" }},
		{name: "missing CA", mutate: func(c *substrateWorkerConfig) { c.CAFile = "" }},
		{name: "missing credential bundle", mutate: func(c *substrateWorkerConfig) { c.ClientCredentialBundle = "" }},
		{name: "zero poll interval", mutate: func(c *substrateWorkerConfig) { c.PollInterval = 0 }},
		{name: "page too large", mutate: func(c *substrateWorkerConfig) { c.PageSize = 1001 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base
			tt.mutate(&got)
			if err := got.validate(); err == nil {
				t.Fatalf("validate() accepted invalid config: %+v", got)
			}
		})
	}
}

func assignedWorker(podName, podUID string, version int64) *substrateapi.Worker {
	return &substrateapi.Worker{
		Metadata:        &substrateapi.ResourceMetadata{Name: "worker-resource-a", Version: version},
		WorkerNamespace: "workers",
		WorkerPool:      "pool-a",
		WorkerPod:       podName,
		WorkerPodUid:    podUID,
		Status: &substrateapi.WorkerStatus{Assignment: &substrateapi.ActorAssignment{
			ActorTemplate: &substrateapi.KubeNamespacedObjectRef{Namespace: "templates", Name: "python-agent"},
			Actor:         &substrateapi.ObjectRef{Atespace: "tenant-a", Name: "actor-a"},
			ActorUid:      "actor-uid-a",
		}},
	}
}
