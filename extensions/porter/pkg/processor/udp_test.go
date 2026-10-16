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
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestConnectUDPIdentityOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fallback     bool
		mismatch     bool
		unknown      bool
		badSandbox   bool
		disconnected bool
	}{
		{name: "headers"},
		{name: "IP fallback", fallback: true},
		{name: "certificate mismatch", fallback: true, mismatch: true},
		{name: "unknown workload", unknown: true},
		{name: "sandbox mismatch", badSandbox: true},
		{name: "disconnected discovery", disconnected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &memorySource{values: map[string]*anypb.Any{
				model.WorkloadType + "/" + testUID: pack(t, fallbackWorkload(t)),
				model.WorkloadType + "//10.0.0.7":  pack(t, fallbackWorkload(t)),
				model.SandboxType + "/sandbox": pack(
					t,
					&sandbox.Sandbox{Uid: "sandbox", Attester: &sandbox.Sandbox_Attester{WorkloadUid: testUID}},
				),
			}}
			if tc.unknown {
				delete(source.values, model.WorkloadType+"/"+testUID)
			}
			if tc.badSandbox {
				source.values[model.SandboxType+"/sandbox"] = pack(
					t,
					&sandbox.Sandbox{Uid: "sandbox", Attester: &sandbox.Sandbox_Attester{WorkloadUid: "other"}},
				)
			}
			if tc.disconnected {
				source.err = errors.New("ADS disconnected")
			}
			conn := testGRPC(t, func(server *grpc.Server, _ *grpc.ClientConn) {
				extproc.RegisterExternalProcessorServer(
					server,
					&Server{Handler: NewPolicyHandler(source, "Kubernetes"), Timeout: time.Second},
				)
			})
			message := connectMessage("")
			message.GetRequestHeaders().GetHeaders().Headers[0] = &core.HeaderValue{
				Key:      ":method",
				RawValue: []byte("GET"),
			}
			message.GetRequestHeaders().GetHeaders().Headers = append(
				message.GetRequestHeaders().GetHeaders().Headers,
				&core.HeaderValue{Key: "upgrade", RawValue: []byte("connect-udp")},
			)
			fields := message.Attributes[model.ExtProcAttributesKey].Fields
			fields[model.AttributeSandboxID] = structpb.NewStringValue("sandbox")
			if tc.fallback {
				delete(fields, model.AttributeWorkloadName)
				delete(fields, model.AttributeWorkloadNamespace)
				fields[model.AttributePeerIP] = structpb.NewStringValue("10.0.0.7")
				principal := peerPrincipal
				if tc.mismatch {
					principal = "spiffe://cluster.local/ns/demo/sa/other"
				}
				fields[model.AttributePeerPrincipal] = structpb.NewStringValue(principal)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			stream, err := extproc.NewExternalProcessorClient(conn).Process(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(message); err != nil {
				t.Fatal(err)
			}
			response, err := stream.Recv()
			if tc.disconnected {
				if status.Code(err) != codes.Unavailable {
					t.Fatalf("response=%v err=%v", response, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.mismatch || tc.unknown || tc.badSandbox {
				if response.GetImmediateResponse().GetStatus().GetCode() != 403 {
					t.Fatalf("identity failure accepted: %v", response)
				}
				return
			}
			metadata := response.GetDynamicMetadata().GetFields()[model.GatewayMetadataNamespace].GetStructValue().
				AsMap()
			workload, ok := metadata["workload"].(map[string]any)
			if response.GetImmediateResponse() != nil || !ok || workload["name"] != "client" ||
				workload["namespace"] != "demo" {
				t.Fatalf("identity not restored: %v", response)
			}
			if _, found := metadata["sni"]; found {
				t.Fatal("UDP must not emit TCP SNI policy")
			}
		})
	}
}

func TestPorterRejectsOtherUpgrades(t *testing.T) {
	for _, upgrade := range []string{"", "websocket"} {
		t.Run(upgrade, func(t *testing.T) {
			conn := testGRPC(t, func(server *grpc.Server, _ *grpc.ClientConn) {
				extproc.RegisterExternalProcessorServer(server, &Server{
					Timeout: time.Second,
					Handler: handlerFunc(func(context.Context, Request) (Result, error) {
						t.Error("unrelated HTTP request reached identity processing")
						return Result{}, nil
					}),
				})
			})
			message := connectMessage("")
			message.GetRequestHeaders().GetHeaders().Headers[0].Value = "GET"
			message.GetRequestHeaders().GetHeaders().Headers = append(
				message.GetRequestHeaders().GetHeaders().Headers,
				&core.HeaderValue{Key: "upgrade", Value: upgrade},
			)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			stream, err := extproc.NewExternalProcessorClient(conn).Process(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(message); err != nil {
				t.Fatal(err)
			}
			_, err = stream.Recv()
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
