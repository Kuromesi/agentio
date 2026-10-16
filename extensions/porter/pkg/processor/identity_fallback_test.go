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
	"net/netip"
	"reflect"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

const peerPrincipal = "spiffe://cluster.local/ns/demo/sa/client"

func fallbackWorkload(t *testing.T) *workload.Workload {
	t.Helper()
	return &workload.Workload{
		Uid:            testUID,
		Name:           "client",
		Namespace:      "demo",
		TrustDomain:    "cluster.local",
		ServiceAccount: "client",
		Extensions: []*workload.Extension{
			{Name: "sni", Config: sniPolicy(t, "*", extensions.SniAction_SNI_ACTION_TLS_TERMINATION)},
		},
	}
}

func TestWorkloadIPFallback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ip        string
		principal string
		claimed   WorkloadIdentity
		change    func(*workload.Workload)
		missing   bool
		deny      bool
	}{
		{name: "IPv4", ip: "10.0.0.7", principal: peerPrincipal},
		{name: "IPv6", ip: "2001:db8::7", principal: peerPrincipal},
		{name: "mapped IPv4", ip: "::ffff:10.0.0.7", principal: peerPrincipal},
		{name: "namespace supplied", ip: "10.0.0.7", principal: peerPrincipal, claimed: WorkloadIdentity{Namespace: "demo"}},
		{name: "name supplied", ip: "10.0.0.7", principal: peerPrincipal, claimed: WorkloadIdentity{Name: "client"}},
		{name: "missing IP", principal: peerPrincipal, deny: true},
		{name: "invalid IP", ip: "not-an-ip", principal: peerPrincipal, deny: true},
		{name: "missing certificate identity", ip: "10.0.0.7", deny: true},
		{name: "wrong namespace", ip: "10.0.0.7", principal: "spiffe://cluster.local/ns/other/sa/client", deny: true},
		{name: "wrong account", ip: "10.0.0.7", principal: "spiffe://cluster.local/ns/demo/sa/other", deny: true},
		{name: "wrong trust domain", ip: "10.0.0.7", principal: "spiffe://other.local/ns/demo/sa/client", deny: true},
		{name: "conflicting partial header", ip: "10.0.0.7", principal: peerPrincipal, claimed: WorkloadIdentity{Name: "other"}, deny: true},
		{name: "unknown IP", ip: "10.0.0.7", principal: peerPrincipal, missing: true, deny: true},
		{name: "host network", ip: "10.0.0.7", principal: peerPrincipal, change: func(w *workload.Workload) { w.NetworkMode = workload.NetworkMode_HOST_NETWORK }, deny: true},
		{name: "no workload identity", ip: "10.0.0.7", principal: peerPrincipal, change: func(w *workload.Workload) { w.ServiceAccount = "" }, deny: true},
		{name: "foreign cluster", ip: "10.0.0.7", principal: peerPrincipal, change: func(w *workload.Workload) { w.Uid = "another//Pod/demo/client" }, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := fallbackWorkload(t)
			if tc.change != nil {
				tc.change(w)
			}
			source := &memorySource{values: map[string]*anypb.Any{}}
			ip, err := netip.ParseAddr(tc.ip)
			if err == nil && !tc.missing {
				source.values[model.WorkloadType+"/"+"/"+ip.Unmap().String()] = pack(t, w)
			}
			result, err := NewPolicyHandler(source, "Kubernetes").Handle(t.Context(), Request{Source: Source{
				PeerIP:    tc.ip,
				Principal: tc.principal,
				Workload:  tc.claimed,
			}})
			if err != nil || (result.DenyStatus != 0) != tc.deny {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if tc.deny {
				return
			}
			want := map[string]any{"name": "client", "namespace": "demo"}
			if !reflect.DeepEqual(result.Metadata["workload"], want) || action(result) != "terminate" {
				t.Fatalf("lost resolved identity or policy: %+v", result)
			}
		})
	}
}

func TestCompleteHeadersDoNotFallBackToIP(t *testing.T) {
	source := &memorySource{
		values: map[string]*anypb.Any{model.WorkloadType + "//10.0.0.7": pack(t, fallbackWorkload(t))},
	}
	result, err := NewPolicyHandler(source, "Kubernetes").Handle(t.Context(), Request{Source: Source{
		Workload:  WorkloadIdentity{Name: "deleted", Namespace: "demo"},
		PeerIP:    "10.0.0.7",
		Principal: peerPrincipal,
	}})
	if err != nil || result.DenyStatus != 403 ||
		!reflect.DeepEqual(source.calls, []string{model.WorkloadType + "/Kubernetes//Pod/demo/deleted"}) {
		t.Fatalf("header failure changed identity: %+v, %v, calls=%v", result, err, source.calls)
	}
}

func TestFallbackPreservesSandboxBindingAndDiscoveryErrors(t *testing.T) {
	for _, owner := range []string{testUID, "another-workload"} {
		source := &memorySource{
			values: map[string]*anypb.Any{model.WorkloadType + "//10.0.0.7": pack(t, fallbackWorkload(t))},
		}
		// Reuse the existing Sandbox fixture through its wire schema.
		source.values[model.SandboxType+"/sandbox"] = pack(
			t,
			&sandbox.Sandbox{Uid: "sandbox", Attester: &sandbox.Sandbox_Attester{WorkloadUid: owner}},
		)
		result, err := NewPolicyHandler(
			source,
			"Kubernetes",
		).Handle(t.Context(), Request{Source: Source{PeerIP: "10.0.0.7", Principal: peerPrincipal, SandboxID: "sandbox"}})
		if err != nil || (result.DenyStatus == 0) != (owner == testUID) {
			t.Fatalf("owner=%s result=%+v error=%v", owner, result, err)
		}
	}
	source := &memorySource{err: errors.New("ADS disconnected")}
	_, err := NewPolicyHandler(
		source,
		"Kubernetes",
	).Handle(t.Context(), Request{Source: Source{PeerIP: "10.0.0.7", Principal: peerPrincipal}})
	if !errors.Is(err, source.err) {
		t.Fatalf("discovery error lost: %v", err)
	}
}

func TestOldClientIdentityFallbackOverGRPC(t *testing.T) {
	ads := &demandADS{
		updates:       make(chan *discovery.DeltaDiscoveryResponse),
		subscriptions: make(chan *discovery.DeltaDiscoveryRequest, 10),
		initial: &discovery.Resource{
			Name:     testUID,
			Aliases:  []string{"/10.0.0.7"},
			Version:  "1",
			Resource: pack(t, fallbackWorkload(t)),
		},
	}
	var source *xdsclient.Client
	conn := testGRPC(t, func(server *grpc.Server, conn *grpc.ClientConn) {
		discovery.RegisterAggregatedDiscoveryServiceServer(server, ads)
		var err error
		source, err = xdsclient.New(
			conn,
			xdsclient.Config{Node: &core.Node{Id: "agentio-porter~test"}, Watches: Watches()},
		)
		if err != nil {
			t.Fatal(err)
		}
		extproc.RegisterExternalProcessorServer(
			server,
			&Server{Timeout: time.Second, Handler: NewPolicyHandler(source, "Kubernetes")},
		)
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- source.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	message := connectMessage("")
	message.Attributes[model.ExtProcAttributesKey] = &structpb.Struct{Fields: map[string]*structpb.Value{
		model.AttributePeerIP: structpb.NewStringValue("10.0.0.7"),
		model.AttributePeerPrincipal: structpb.NewStructValue(
			&structpb.Struct{Fields: map[string]*structpb.Value{"value": structpb.NewStringValue(peerPrincipal)}},
		),
	}}
	// Request headers must not override connection attributes or the discovered Pod.
	message.GetRequestHeaders().GetHeaders().Headers = append(message.GetRequestHeaders().GetHeaders().Headers,
		&core.HeaderValue{Key: "x-agentio-workload-name", Value: "forged"},
		&core.HeaderValue{Key: "forwarded", Value: "for=10.0.0.99"})
	callCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	stream, err := extproc.NewExternalProcessorClient(conn).Process(callCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(message); err != nil {
		t.Fatal(err)
	}
	result, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	metadata := result.GetDynamicMetadata().GetFields()["agentio"].GetStructValue().AsMap()
	if result.GetImmediateResponse() != nil ||
		!reflect.DeepEqual(metadata["workload"], map[string]any{"name": "client", "namespace": "demo"}) {
		t.Fatalf("fallback did not resolve IP alias through ADS: %v", result)
	}
}
