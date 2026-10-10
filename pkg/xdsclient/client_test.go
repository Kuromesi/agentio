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

package xdsclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testType = "type.googleapis.com/google.protobuf.StringValue"

type fakeADS struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	streams chan discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	done    chan struct{}
}

func (s *fakeADS) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	select {
	case s.streams <- stream:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	select {
	case <-s.done:
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

func TestDemandUpdateRemovalAndDisconnect(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	ads := &fakeADS{
		streams: make(chan discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer, 4),
		done:    make(chan struct{}),
	}
	srv := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(srv, ads)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := New(conn, Config{Node: &core.Node{Id: "test"}, Watches: []Watch{{TypeURL: testType}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() {
		if err := c.Run(ctx); err != nil {
			t.Error(err)
		}
	}()
	var stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	select {
	case stream = <-ads.streams:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	initial, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.ResourceNamesSubscribe) != 1 || initial.ResourceNamesSubscribe[0] != "*" ||
		len(initial.ResourceNamesUnsubscribe) != 1 {
		t.Fatalf("not an empty on-demand watch: %v", initial)
	}
	result := make(chan error, 1)
	go func() {
		_, err := c.Demand(ctx, testType, "a")
		result <- err
	}()
	sub, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.ResourceNamesSubscribe) != 1 || sub.ResourceNamesSubscribe[0] != "a" {
		t.Fatalf("demand: %v", sub)
	}
	value, err := anypb.New(wrapperspb.String("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DeltaDiscoveryResponse{
			TypeUrl:   testType,
			Nonce:     "1",
			Resources: []*discovery.Resource{{Name: "a", Version: "1", Resource: value}},
		},
	); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ack, err := stream.Recv()
	if err != nil || ack.ResponseNonce != "1" || ack.ErrorDetail != nil {
		t.Fatalf("ack %v %v", ack, err)
	}
	if len(c.Snapshot().Resources[testType]) != 1 {
		t.Fatal("demand returned before cache publication")
	}
	if err := stream.Send(
		&discovery.DeltaDiscoveryResponse{TypeUrl: testType, Nonce: "2", RemovedResources: []string{"a"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if len(c.Snapshot().Resources[testType]) != 0 {
		t.Fatal("deleted resource retained")
	}
	close(ads.done)
	deadline := time.After(time.Second)
	for c.Snapshot().Synced[testType] {
		select {
		case <-deadline:
			t.Fatal("disconnected cache remains ready")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestNACKReconnectReplaysDemandAndWakesAllWaiters(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	ads := &fakeADS{
		streams: make(chan discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer, 4),
		done:    make(chan struct{}),
	}
	srv := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(srv, ads)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := New(conn, Config{Node: &core.Node{Id: "test"}, Watches: []Watch{{TypeURL: testType}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() {
		if err := c.Run(ctx); err != nil {
			t.Error(err)
		}
	}()
	stream := <-ads.streams
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := c.Demand(ctx, testType, "a")
			results <- err
		}()
	}
	request, err := stream.Recv()
	if err != nil || len(request.ResourceNamesSubscribe) != 1 {
		t.Fatalf("demand %v %v", request, err)
	}
	wrong, err := anypb.New(wrapperspb.Bool(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DeltaDiscoveryResponse{
			TypeUrl:   testType,
			Nonce:     "bad",
			Resources: []*discovery.Resource{{Name: "a", Version: "1", Resource: wrong}},
		},
	); err != nil {
		t.Fatal(err)
	}
	nack, err := stream.Recv()
	if err != nil || nack.ErrorDetail == nil || nack.ResponseNonce != "bad" {
		t.Fatalf("NACK %v %v", nack, err)
	}
	if _, ready := c.Observe(testType); ready {
		t.Fatal("rejected response became ready")
	}
	select {
	case stream = <-ads.streams:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	initial, err := stream.Recv()
	if err != nil || len(initial.ResourceNamesSubscribe) != 1 || initial.ResourceNamesSubscribe[0] != "a" ||
		len(initial.InitialResourceVersions) != 0 {
		t.Fatalf("reconnect lost demand %v %v", initial, err)
	}
	good, err := anypb.New(wrapperspb.String("ok"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DeltaDiscoveryResponse{
			TypeUrl:   testType,
			Nonce:     "good",
			Resources: []*discovery.Resource{{Name: "a", Version: "2", Resource: good}},
		},
	); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	snapshot := c.Snapshot()
	snapshot.Resources[testType]["a"].Value = nil
	if len(c.Snapshot().Resources[testType]["a"].Value) == 0 {
		t.Fatal("caller mutated shared cache")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := c.Demand(canceled, testType, "missing"); err == nil {
		t.Fatal("canceled demand succeeded")
	}
}

func TestAliasesResolveWithoutDuplicatingSnapshotResources(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	c, err := New(conn, Config{Node: &core.Node{Id: "test"}, Watches: []Watch{{TypeURL: testType, Wildcard: true}}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := anypb.New(wrapperspb.String("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.apply(
		&discovery.DeltaDiscoveryResponse{
			TypeUrl:   testType,
			Resources: []*discovery.Resource{{Name: "canonical", Aliases: []string{"alias"}, Resource: value}},
		},
	); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := c.Demand(ctx, testType, "alias"); err != nil {
		t.Fatal(err)
	}
	if len(c.Snapshot().Resources[testType]) != 1 {
		t.Fatal("aliases duplicate resources")
	}
	if err := c.apply(
		&discovery.DeltaDiscoveryResponse{TypeUrl: testType, RemovedResources: []string{"canonical"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Demand(ctx, testType, "alias"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed alias: %v", err)
	}
}

func TestSharedAliasBecomesUnambiguousAfterRemoval(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := New(conn, Config{Node: &core.Node{Id: "test"}, Watches: []Watch{{TypeURL: testType, Wildcard: true}}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := anypb.New(wrapperspb.String("shared"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType,
		Resources: []*discovery.Resource{
			{Name: "a", Aliases: []string{"shared-ip"}, Resource: value},
			{Name: "b", Aliases: []string{"shared-ip"}, Resource: value},
		}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := c.Demand(ctx, testType, "shared-ip"); err == nil {
		t.Fatal("ambiguous alias selected a workload")
	}
	if len(c.Snapshot().Resources[testType]) != 2 {
		t.Fatal("shared alias lost canonical resources")
	}
	if err := c.apply(
		&discovery.DeltaDiscoveryResponse{TypeUrl: testType, RemovedResources: []string{"a"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Demand(ctx, testType, "shared-ip"); err != nil {
		t.Fatal(err)
	}
}

func TestObserveCapturesReadinessAndNotification(t *testing.T) {
	c := &Client{changed: make(chan struct{}), types: map[string]*typeState{testType: {}}}
	changed, ready := c.Observe(testType)
	if ready || c.Snapshot().Changed != changed {
		t.Fatal("observation does not describe the current snapshot")
	}
	// Publish between observing state and starting to wait. The closed channel
	// must still deliver the update, without a revision check.
	c.mu.Lock()
	c.types[testType].synced = true
	c.notifyLocked()
	c.mu.Unlock()
	select {
	case <-changed:
	default:
		t.Fatal("update before wait was lost")
	}
	next, ready := c.Observe(testType)
	if !ready || next == changed || c.Snapshot().Changed != next {
		t.Fatal("publication did not replace the notification")
	}
	if _, ready := c.Observe("unwatched"); ready {
		t.Fatal("unwatched resource reported ready")
	}
}
