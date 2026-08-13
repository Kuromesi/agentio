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

// Assembly-level test: proves server.New wires the profile store, plugin
// chain, and audit logger into a working ExternalProcessor over a real
// gRPC transport — the one layer the in-process enginetest harness skips.
package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	runserver "istio.io/istio/extensions/epe/pkg/server"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
	"istio.io/istio/extensions/epe/pkg/testing/securityprofiletest"
	"istio.io/istio/extensions/epe/pkg/wiring"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestAsRunnable_ServesConfiguredChainOverGRPC(t *testing.T) {
	fixture := securityprofiletest.NewFixture(t)
	fixture.ApplyYAML(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: grpc-block
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /grpc/blocked
    actions:
      block:
        statusCode: 451
        body: blocked-over-grpc
`)

	port := freePort(t)
	regs, err := wiring.BuildFilters(wiring.Deps{Kube: k8sfake.NewClientset()})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	rn := runserver.New(runserver.Config{
		GrpcPort:      port,
		Resolve:       securityprofile.NewResolver(fixture.Store, regs, nil),
		Registrations: regs,
	}, logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- rn.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := extProcPb.NewExternalProcessorClient(conn)

	run := func(path string) *enginetest.Verdict {
		t.Helper()
		msgs := enginetest.NewRequest("GET", "server.example.com", path).
			Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
			Build()

		var responses []*extProcPb.ProcessingResponse
		deadline := time.Now().Add(10 * time.Second)
		for {
			responses = responses[:0]
			stream, err := client.Process(ctx)
			if err == nil {
				err = sendAll(stream, msgs)
			}
			if err == nil {
				responses, err = recvAll(stream)
			}
			if err == nil {
				return enginetest.ParseVerdict(responses, nil)
			}
			if time.Now().After(deadline) {
				t.Fatalf("Process against real gRPC server: %v", err)
			}
			// The listener may not be accepting yet right after startup.
			time.Sleep(50 * time.Millisecond)
		}
	}

	run("/grpc/blocked").RequireBlockedBody(t, 451, "blocked-over-grpc")
	run("/grpc/open").RequirePassthrough(t)
}

func sendAll(stream extProcPb.ExternalProcessor_ProcessClient, msgs []*extProcPb.ProcessingRequest) error {
	for _, msg := range msgs {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	return stream.CloseSend()
}

func recvAll(stream extProcPb.ExternalProcessor_ProcessClient) ([]*extProcPb.ProcessingResponse, error) {
	var responses []*extProcPb.ProcessingResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return responses, nil
		}
		if err != nil {
			return nil, err
		}
		responses = append(responses, resp)
	}
}
