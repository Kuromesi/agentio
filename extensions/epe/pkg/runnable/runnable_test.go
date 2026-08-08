// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package runnable

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// freePort returns an OS-assigned free TCP port. The listener is closed
// immediately, leaving a brief race window — acceptable for tests.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// TestGRPCServer_StartsAndStopsViaContext starts the runnable in a goroutine
// and cancels the context to drive a graceful shutdown.
func TestGRPCServer_StartsAndStopsViaContext(t *testing.T) {
	srv := grpc.NewServer()
	r := GRPCServer("test", srv, freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	// Give the server time to bind, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil from runnable on graceful stop, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runnable did not exit within 2s after cancel")
	}
}

// TestGRPCServer_GracefulStopBoundedByDeadline pins the shutdown contract
// against a stream parked in Recv. GracefulStop only sends GOAWAY — it does
// not cancel open streams — so an ext_proc handler blocked in Recv() on a
// quiet Envoy holds the drain open forever. The runnable must fall back to a
// hard Stop once the grace period expires; Stop closes the transport, which
// errors the pending Recv and lets the handler (and GracefulStop) finish.
func TestGRPCServer_GracefulStopBoundedByDeadline(t *testing.T) {
	handlerRunning := make(chan struct{})

	// The handler is dispatched as soon as the stream's headers arrive and
	// then parks in RecvMsg — exactly like an ext_proc stream waiting on a
	// quiet Envoy. The client never sends a message, so only a transport
	// teardown can release it.
	srv := grpc.NewServer(grpc.UnknownServiceHandler(
		func(_ any, stream grpc.ServerStream) error {
			close(handlerRunning)
			var m any
			return stream.RecvMsg(&m)
		}))

	port := freePort(t)
	r := GRPCServer("stuck", srv, port, WithGracefulStopTimeout(200*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	conn, err := grpc.NewClient("127.0.0.1:"+strconv.Itoa(port),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.NewStream(context.Background(),
		&grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/stuck.Service/Hang"); err != nil {
		t.Fatalf("open stream: %v", err)
	}

	select {
	case <-handlerRunning:
	case <-time.After(5 * time.Second):
		t.Fatal("stuck handler never started; test cannot exercise the shutdown path")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown blocked on the stuck stream: GracefulStop is not bounded by a deadline")
	}
}

// TestGRPCServer_ListenError exercises the listener-failure branch by
// pre-binding a port on all interfaces (matching the runnable's wildcard
// listen) and asking the runnable to bind the same one.
func TestGRPCServer_ListenError(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("pre-bind failed: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	r := GRPCServer("conflict", grpc.NewServer(), port)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { done <- r.Start(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected listen error when the port is already bound")
		}
	case <-ctx.Done():
		t.Fatal("runnable did not return within 2s on bind conflict")
	}
}

// TestHTTPServer_StartsAndStopsViaContext starts the HTTP runnable in a
// goroutine and cancels the context to drive a graceful shutdown.
func TestHTTPServer_StartsAndStopsViaContext(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	r := HTTPServer("test", http.NotFoundHandler(), addr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	// Give the server time to bind, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil from runnable on graceful stop, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runnable did not exit within 2s after cancel")
	}
}

// TestHTTPServer_ListenError exercises the listener-failure branch by
// pre-binding an address and asking the runnable to bind the same one.
func TestHTTPServer_ListenError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind failed: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	r := HTTPServer("conflict", http.NotFoundHandler(), addr)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { done <- r.Start(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected listen error when the address is already bound")
		}
	case <-ctx.Done():
		t.Fatal("runnable did not return within 2s on bind conflict")
	}
}

func TestGroup(t *testing.T) {
	t.Run("group cancels remaining members on first failure", func(t *testing.T) {
		boom := errors.New("boom")
		var g Group
		peerStopped := make(chan struct{})
		g.Add(Func(func(ctx context.Context) error {
			<-ctx.Done()
			close(peerStopped)
			return nil
		}))
		g.Add(Func(func(ctx context.Context) error {
			return boom
		}))

		if err := g.Start(context.Background()); !errors.Is(err, boom) {
			t.Errorf("expected the member failure, got %v", err)
		}
		select {
		case <-peerStopped:
		default:
			t.Error("expected the peer member to be cancelled after the failure")
		}
	})

	t.Run("group stops cleanly on context cancellation", func(t *testing.T) {
		var g Group
		g.Add(Func(func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		}))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- g.Start(ctx) }()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("expected nil on graceful shutdown, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("group did not stop within 2s")
		}
	})
}
