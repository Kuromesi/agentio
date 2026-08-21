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
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/substrateapi"
)

func TestActorBindingFromLegacySubstrateWorkerWire(t *testing.T) {
	template := appendStringField(nil, 1, "templates")
	template = appendStringField(template, 2, "python-agent")
	actorRef := appendStringField(nil, 1, "tenant-a")
	actorRef = appendStringField(actorRef, 2, "actor-a")
	assignment := protowire.AppendTag(nil, 1, protowire.BytesType)
	assignment = protowire.AppendBytes(assignment, template)
	assignment = protowire.AppendTag(assignment, 2, protowire.BytesType)
	assignment = protowire.AppendBytes(assignment, actorRef)
	assignment = appendStringField(assignment, 3, "actor-uid-a")
	worker := appendStringField(nil, 1, "workers")
	worker = appendStringField(worker, 2, "pool-a")
	worker = appendStringField(worker, 3, "worker-a")
	worker = protowire.AppendTag(worker, 4, protowire.BytesType)
	worker = protowire.AppendBytes(worker, assignment)
	worker = protowire.AppendTag(worker, 6, protowire.VarintType)
	worker = protowire.AppendVarint(worker, 9)
	worker = appendStringField(worker, 7, "pod-uid-a")

	key, got, assigned, err := actorBindingFromWorkerWire(worker)
	if err != nil {
		t.Fatalf("actorBindingFromWorkerWire() failed: %v", err)
	}
	if !assigned {
		t.Fatal("actorBindingFromWorkerWire() did not recognize legacy assignment")
	}
	if key != (workerPodKey{namespace: "workers", name: "worker-a", uid: "pod-uid-a"}) {
		t.Fatalf("Worker key = %+v, want legacy Pod identity", key)
	}
	if got.GetActorUid() != "actor-uid-a" || got.GetGeneration() != 9 {
		t.Fatalf("ActorContext = %+v, want legacy Actor generation 9", got)
	}
}

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
			Workers:       [][]byte{marshalWorker(t, assignedWorker("worker-a", "pod-uid-a", 9))},
			NextPageToken: "page-2",
		},
		"page-2": {
			Workers: [][]byte{marshalWorker(t, &substrateapi.Worker{
				Metadata:        &substrateapi.ResourceMetadata{Version: 4},
				WorkerNamespace: "workers",
				WorkerPool:      "pool-b",
				WorkerPod:       "worker-b",
				WorkerPodUid:    "pod-uid-b",
				Status:          &substrateapi.WorkerStatus{},
			})},
		},
	}}
	var changes [][]workerPodKey
	source := newSubstrateWorkerSourceForClient(client, substrateWorkerConfig{
		PageSize:   1,
		RPCTimeout: time.Second,
	}, func(keys []workerPodKey) { changes = append(changes, keys) })

	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("refresh() failed: %v", err)
	}
	if len(client.requests) != 2 || client.requests[0].GetPageSize() != 1 || client.requests[1].GetPageToken() != "page-2" {
		t.Fatalf("ListWorkers requests = %+v, want two paginated requests", client.requests)
	}
	if len(changes) != 1 || len(changes[0]) != 1 || changes[0][0] != (workerPodKey{namespace: "workers", name: "worker-a", uid: "pod-uid-a"}) {
		t.Fatalf("change notifications = %+v, want assigned worker-a", changes)
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
		"": {Workers: [][]byte{marshalWorker(t, assignedWorker("worker-a", "pod-uid-a", 9))}},
	}}
	var changes [][]workerPodKey
	source := newSubstrateWorkerSourceForClient(client, substrateWorkerConfig{
		PageSize:   1000,
		RPCTimeout: time.Second,
	}, func(keys []workerPodKey) { changes = append(changes, keys) })

	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("first refresh() failed: %v", err)
	}
	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("unchanged refresh() failed: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("change notifications after identical snapshot = %d, want 1", len(changes))
	}

	client.err = errors.New("ateapi unavailable")
	if err := source.refresh(context.Background()); err == nil {
		t.Fatal("refresh() succeeded while ListWorkers failed")
	}
	if got := source.actorContextForWorker("workers", "worker-a", "pod-uid-a"); got == nil {
		t.Fatal("failed refresh discarded the last successful Actor binding")
	}
	if len(changes) != 1 {
		t.Fatalf("change notifications after failed refresh = %d, want 1", len(changes))
	}

	client.err = nil
	client.responses[""] = &substrateapi.ListWorkersResponse{Workers: [][]byte{marshalWorker(t, &substrateapi.Worker{
		Metadata:        &substrateapi.ResourceMetadata{Version: 10},
		WorkerNamespace: "workers",
		WorkerPod:       "worker-a",
		WorkerPodUid:    "pod-uid-a",
		Status:          &substrateapi.WorkerStatus{},
	})}}
	if err := source.refresh(context.Background()); err != nil {
		t.Fatalf("unassigned refresh() failed: %v", err)
	}
	if got := source.actorContextForWorker("workers", "worker-a", "pod-uid-a"); got != nil {
		t.Fatalf("removed Actor binding remained: %+v", got)
	}
	if len(changes) != 2 || len(changes[1]) != 1 || changes[1][0] != (workerPodKey{namespace: "workers", name: "worker-a", uid: "pod-uid-a"}) {
		t.Fatalf("change notifications after removal = %+v, want removed worker-a", changes)
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

func appendStringField(dst []byte, number protowire.Number, value string) []byte {
	dst = protowire.AppendTag(dst, number, protowire.BytesType)
	return protowire.AppendString(dst, value)
}

func marshalWorker(t *testing.T, worker *substrateapi.Worker) []byte {
	t.Helper()
	wire, err := proto.Marshal(worker)
	if err != nil {
		t.Fatalf("proto.Marshal(Worker) failed: %v", err)
	}
	return wire
}
