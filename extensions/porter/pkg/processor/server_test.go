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
	"io"
	"net"
	"slices"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

func connectMessage(sni string) *extproc.ProcessingRequest {
	headers := []*core.HeaderValue{{Key: ":method", Value: "CONNECT"}, {Key: ":authority", Value: "203.0.113.10:443"}}
	if sni != "" {
		headers = append(headers, &core.HeaderValue{Key: HeaderSNI, Value: sni})
	}
	attrs := &structpb.Struct{Fields: map[string]*structpb.Value{
		"filter_state['agentio.workload.name']":      structpb.NewStringValue("client"),
		"filter_state['agentio.workload.namespace']": structpb.NewStringValue("demo"),
	}}
	return &extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extproc.HttpHeaders{Headers: &core.HeaderMap{Headers: headers}},
		},
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": attrs},
	}
}
func testGRPC(t *testing.T, setup func(*grpc.Server, *grpc.ClientConn)) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	conn, err := grpc.NewClient(
		"passthrough:///connect-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	setup(server, conn)
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	return conn
}
func callConnect(t *testing.T, conn *grpc.ClientConn) *extproc.ProcessingResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	stream, err := extproc.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(connectMessage("API.Example.com.")); err != nil {
		t.Fatal(err)
	}
	result, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	// Server must finish without waiting for the client to close its send side.
	if _, err = stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("CONNECT stream remains open: %v", err)
	}
	return result
}
func TestGenericConnectStage(t *testing.T) {
	conn := testGRPC(t, func(server *grpc.Server, _ *grpc.ClientConn) {
		extproc.RegisterExternalProcessorServer(server, &Server{Timeout: time.Second,
			Handle: func(_ context.Context, request Request) (Result, error) {
				if request.Authority != "203.0.113.10:443" || request.Source.Workload.Name != "client" ||
					request.Headers.SNI != "api.example.com" {
					t.Errorf("request: %+v", request)
				}
				return Result{Metadata: map[string]any{"classified": true}}, nil
			}})
	})
	result := callConnect(t, conn)
	if !result.GetDynamicMetadata().GetFields()["agentio"].GetStructValue().GetFields()["classified"].GetBoolValue() {
		t.Fatalf("generic metadata: %v", result)
	}
	for _, message := range []*extproc.ProcessingRequest{
		{Request: &extproc.ProcessingRequest_RequestBody{RequestBody: &extproc.HttpBody{}}},
		{Request: &extproc.ProcessingRequest_RequestHeaders{RequestHeaders: &extproc.HttpHeaders{}}},
	} {
		stream, err := extproc.NewExternalProcessorClient(conn).Process(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = stream.Send(message); err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid protocol accepted: %v", err)
		}
	}
}

type demandADS struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	updates       chan *discovery.DeltaDiscoveryResponse
	subscriptions chan *discovery.DeltaDiscoveryRequest
	initial       *discovery.Resource
	recreate      chan *discovery.Resource
}

func (s *demandADS) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	requests := make(chan *discovery.DeltaDiscoveryRequest)
	go func() {
		defer close(requests)
		for {
			request, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case requests <- request:
			case <-stream.Context().Done():
				return
			}
		}
	}()
	for {
		var reply *discovery.DeltaDiscoveryResponse
		select {
		case <-stream.Context().Done():
			return nil
		case request, ok := <-requests:
			if !ok {
				return nil
			}
			if len(request.ResourceNamesSubscribe) == 0 && len(request.ResourceNamesUnsubscribe) == 0 {
				continue
			}
			select {
			case s.subscriptions <- request:
			case <-stream.Context().Done():
				return nil
			}
			if len(request.ResourceNamesSubscribe) == 0 {
				continue
			}
			reply = &discovery.DeltaDiscoveryResponse{TypeUrl: request.TypeUrl, Nonce: "initial"}
			for _, name := range request.ResourceNamesSubscribe {
				if slices.Contains(request.ResourceNamesUnsubscribe, name) {
					continue
				}
				if request.TypeUrl == model.WorkloadType && name == testUID && s.initial != nil {
					reply.Resources = append(reply.Resources, s.initial)
				} else {
					reply.RemovedResources = append(reply.RemovedResources, name)
				}
			}
		case reply = <-s.updates:
			for _, resource := range reply.Resources {
				s.initial = resource
			}
			if slices.Contains(reply.RemovedResources, testUID) {
				s.initial = nil
			}
		case resource := <-s.recreate:
			s.initial = resource
			continue
		}
		if err := stream.Send(reply); err != nil {
			return err
		}
	}
}
func TestDemandPolicyUpdatesAndRemovalOverGRPC(t *testing.T) {
	initial := sourceWorkload(t, sniPolicy(t, "api.example.com", extensions.SniAction_SNI_ACTION_TLS_TERMINATION))
	ads := &demandADS{
		updates:       make(chan *discovery.DeltaDiscoveryResponse),
		subscriptions: make(chan *discovery.DeltaDiscoveryRequest, 10),
		initial:       &discovery.Resource{Name: testUID, Version: "1", Resource: initial},
		recreate:      make(chan *discovery.Resource),
	}
	var source *xdsclient.Client
	conn := testGRPC(t, func(server *grpc.Server, conn *grpc.ClientConn) {
		discovery.RegisterAggregatedDiscoveryServiceServer(server, ads)
		var err error
		source, err = xdsclient.New(conn, xdsclient.Config{Node: &core.Node{Id: "waypoint~test"}, Watches: Watches()})
		if err != nil {
			t.Fatal(err)
		}
		extproc.RegisterExternalProcessorServer(
			server,
			&Server{Timeout: time.Second, Handle: NewHandler(source, "Kubernetes")},
		)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- source.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for {
		changed, ready := source.Observe(model.WorkloadType, model.SandboxType)
		if ready {
			break
		}
		select {
		case <-changed:
		case <-time.After(3 * time.Second):
			t.Fatal("ADS did not synchronize")
		}
	}
	got := callConnect(t, conn)
	tlsAction := func(r *extproc.ProcessingResponse) string {
		return r.GetDynamicMetadata().GetFields()["agentio"].GetStructValue().GetFields()["tls"].GetStructValue().GetFields()["action"].GetStringValue()
	}
	if tlsAction(got) != "terminate" {
		t.Fatalf("first demand: %v", got)
	}
	for range 3 {
		select {
		case request := <-ads.subscriptions:
			for _, name := range request.ResourceNamesSubscribe {
				if name == "*" && !slices.Contains(request.ResourceNamesUnsubscribe, "*") {
					t.Fatal("wildcard subscription")
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatal("missing named/initial subscription")
		}
	}
	changed := source.Snapshot().Changed
	ads.updates <- &discovery.DeltaDiscoveryResponse{TypeUrl: model.WorkloadType, Nonce: "2", Resources: []*discovery.Resource{{Name: testUID, Version: "2", Resource: sourceWorkload(t, nil)}}}
	select {
	case <-changed:
	case <-time.After(3 * time.Second):
		t.Fatal("policy update not published")
	}
	if got := callConnect(t, conn); tlsAction(got) != "passthrough" {
		t.Fatalf("updated decision: %v", got)
	}
	changed = source.Snapshot().Changed
	ads.updates <- &discovery.DeltaDiscoveryResponse{TypeUrl: model.WorkloadType, Nonce: "3", RemovedResources: []string{testUID}}
	select {
	case <-changed:
	case <-time.After(3 * time.Second):
		t.Fatal("removal not published")
	}
	select {
	case request := <-ads.subscriptions:
		if !slices.Equal(request.ResourceNamesUnsubscribe, []string{testUID}) {
			t.Fatalf("deleted resource not unsubscribed: %v", request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("missing unsubscribe")
	}
	if got := callConnect(t, conn); got.GetImmediateResponse().GetStatus().GetCode() != 403 {
		t.Fatalf("removed source allowed: %v", got)
	}
	for range 2 {
		select {
		case <-ads.subscriptions: // The missing resource was demanded again, then released.
		case <-time.After(3 * time.Second):
			t.Fatal("missing retry subscription/unsubscription")
		}
	}
	ads.recreate <- &discovery.Resource{Name: testUID, Version: "4", Resource: initial}
	if got := callConnect(t, conn); tlsAction(got) != "terminate" {
		t.Fatalf("recreated source was not fetched: %v", got)
	}
}

func TestConnectWrappedAttributesAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler Handler
		code    codes.Code
	}{
		{
			name: "wrapped identity",
			handler: func(_ context.Context, request Request) (Result, error) {
				if request.Source.Workload.Name != "client" || request.Source.Workload.Namespace != "demo" {
					t.Errorf("lost wrapped source: %+v", request.Source)
				}
				if request.Headers.SNI != "" {
					t.Error("expected absent SNI")
				}
				return Result{Metadata: map[string]any{"classified": true}}, nil
			},
		},
		{name: "unavailable", handler: func(context.Context, Request) (Result, error) { return Result{}, errors.New("disconnected") }, code: codes.Unavailable},
		{
			name: "deadline",
			handler: func(ctx context.Context, _ Request) (Result, error) {
				<-ctx.Done()
				return Result{}, ctx.Err()
			},
			code: codes.Unavailable,
		},
		{
			name: "invalid metadata",
			handler: func(context.Context, Request) (Result, error) {
				return Result{Metadata: map[string]any{"unsupported": make(chan int)}}, nil
			},
			code: codes.Internal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := testGRPC(t, func(server *grpc.Server, _ *grpc.ClientConn) {
				extproc.RegisterExternalProcessorServer(
					server,
					&Server{Handle: tc.handler, Timeout: 20 * time.Millisecond},
				)
			})
			message := connectMessage("")
			for key, value := range message.Attributes["envoy.filters.http.ext_proc"].Fields {
				message.Attributes["envoy.filters.http.ext_proc"].Fields[key] = structpb.NewStructValue(
					&structpb.Struct{Fields: map[string]*structpb.Value{"value": value}},
				)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			stream, err := extproc.NewExternalProcessorClient(conn).Process(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = stream.Send(message); err != nil {
				t.Fatal(err)
			}
			response, err := stream.Recv()
			if status.Code(err) != tc.code {
				t.Fatalf("response=%v error=%v, want %v", response, err, tc.code)
			}
			if tc.code == codes.OK &&
				!response.GetDynamicMetadata().GetFields()["agentio"].GetStructValue().GetFields()["classified"].GetBoolValue() {
				t.Fatalf("no-SNI handler not invoked: %v", response)
			}
		})
	}
}
