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

package fakeclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type observed struct {
	request *discovery.DeltaDiscoveryRequest
	address string
	token   string
}

type server struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	requests chan observed
}

func (s *server) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	p, _ := peer.FromContext(stream.Context())
	md, _ := metadata.FromIncomingContext(stream.Context())
	for {
		r, err := stream.Recv()
		if err != nil {
			return err
		}
		select {
		case s.requests <- observed{r, p.Addr.String(), md.Get("authorization")[0]}:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if r.ResponseNonce == "" && len(r.ResourceNamesSubscribe) > 0 {
			if err := stream.Send(
				&discovery.DeltaDiscoveryResponse{
					TypeUrl:          r.TypeUrl,
					Nonce:            "nonce-1",
					RemovedResources: []string{"deleted-resource"},
				},
			); err != nil {
				return err
			}
		}
	}
}
func testServer(t *testing.T) (Config, <-chan observed) {
	t.Helper()
	// Reuse Go's localhost test certificate, but verify it with an explicit CA pool.
	https := httptest.NewTLSServer(nil)
	cert := https.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(https.Certificate())
	https.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(
			credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		),
	)
	s := &server{requests: make(chan observed, 20)}
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, s)
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", err)
		}
	})
	return Config{
		Target:    listener.Addr().String(),
		Node:      &core.Node{Id: "fake-node"},
		TLSConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		Token:     func(context.Context) (string, error) { return "test-token", nil },
	}, s.requests
}
func next(t *testing.T, ch <-chan observed) observed {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(3 * time.Second):
		t.Fatal("missing request")
		return observed{}
	}
}
func TestManualDeltaProtocolAndIndependentConnections(t *testing.T) {
	cfg, requests := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})
	typeURL := "type.googleapis.com/example.CustomResource"
	initial := &discovery.DeltaDiscoveryRequest{
		TypeUrl:                 typeURL,
		ResourceNamesSubscribe:  []string{"*"},
		InitialResourceVersions: map[string]string{"old": "v1"},
	}
	if err := c.Send(initial); err != nil {
		t.Fatal(err)
	}
	first := next(t, requests)
	if first.request.Node.GetId() != cfg.Node.Id || first.token != "Bearer test-token" ||
		first.request.InitialResourceVersions["old"] != "v1" {
		t.Fatalf("initial request: %+v", first)
	}
	if initial.Node != nil {
		t.Fatal("Send mutated caller's request")
	}
	response, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if response.RemovedResources[0] != "deleted-resource" {
		t.Fatal("removed resources not preserved")
	}
	// A receive does not automatically ACK: scenarios own ACK timing and validation.
	select {
	case <-requests:
		t.Fatal("unexpected automatic request")
	default:
	}
	if err := c.NACK(response, "intentional invalid resource"); err != nil {
		t.Fatal(err)
	}
	nack := next(t, requests).request
	if nack.TypeUrl != typeURL || nack.ResponseNonce != "nonce-1" ||
		nack.ErrorDetail.GetCode() != int32(codes.InvalidArgument) ||
		nack.Node != nil {
		t.Fatalf("NACK: %v", nack)
	}
	if err := c.ACK(response); err != nil {
		t.Fatal(err)
	}
	ack := next(t, requests).request
	if ack.ResponseNonce != response.Nonce || ack.ErrorDetail != nil {
		t.Fatalf("ACK: %v", ack)
	}
	if err := c.Unsubscribe(typeURL, "old"); err != nil {
		t.Fatal(err)
	}
	if next(t, requests).request.ResourceNamesUnsubscribe[0] != "old" {
		t.Fatal("unsubscribe not sent")
	}
	other, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := other.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})
	if err := other.Subscribe(typeURL, "named"); err != nil {
		t.Fatal(err)
	}
	second := next(t, requests)
	if second.address == first.address || second.request.Node == nil {
		t.Fatal("Open must create an independent transport and initial Node")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Recv(); err == nil {
		t.Fatal("Close did not cancel receive")
	}
}
func TestContextCancellationWithoutResponse(t *testing.T) {
	cfg, requests := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})
	if err := c.Subscribe("type.googleapis.com/example.Silent"); err != nil {
		t.Fatal(err)
	}
	next(t, requests)
	cancel()
	if _, err := c.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
func TestFileTokenRotationAndInvalidTransport(t *testing.T) {
	cfg, requests := testServer(t)
	path := filepath.Join(t.TempDir(), "token")
	cfg.Token = FileToken(path)
	for _, token := range []string{"first", "rotated"} {
		if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := Open(ctx, cfg)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := c.Subscribe("type.googleapis.com/example.Resource"); err != nil {
			t.Fatal(err)
		}
		if got := next(t, requests).token; got != "Bearer "+token {
			t.Fatalf("got %q", got)
		}
		if err := c.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
		cancel()
	}
	cfg.TLSConfig = nil
	if _, err := Open(context.Background(), cfg); err == nil {
		t.Fatal("implicit plaintext accepted")
	}
}
