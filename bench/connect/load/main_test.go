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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	sharedload "github.com/openkruise/agentio/bench/load"
)

func TestProcStatUnitsAndCommandParentheses(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[11] = "250"
	fields[12] = "50"
	fields[21] = "42"
	got, err := parseSample("123 (worker (name)) "+strings.Join(fields, " "), 100, 4096)
	if err != nil || got.CPU != 3 || got.RSS != 42*4096 {
		t.Fatalf("sample=%+v error=%v", got, err)
	}
	if _, err := parseSample("broken", 100, 4096); err == nil {
		t.Fatal("malformed stat accepted")
	}
}

func TestInvalidLoadArguments(t *testing.T) {
	for _, args := range [][]string{{"-streams=0"}, {"-connections=0"}, {"-direction=X"}, {"-duration=0s"}, {"-warmup=-1s"}, {"-ticks=0"}, {"unexpected"}} {
		if _, err := parseConfig(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSetupCompletionKeepsTunnelAliveAndCancellationClosesIt(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	serverDone := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if _, err := fmt.Fprint(w, "payload"); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(serverDone)
	})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: nil}
	// Reuse the same transport setup as runLoad, with no TLS on the fixture listener.
	tr.DialTLSContext = func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	streams := &transfers{
		ctx:        ctx,
		config:     config{Streams: 1, Direction: "D"},
		transports: []*http2.Transport{tr},
		received:   make([]atomic.Uint64, 1),
		failures:   map[int]error{},
	}
	defer tr.CloseIdleConnections()
	result, err := sharedload.Run(
		ctx,
		sharedload.Config{Requests: 1, Identities: 1, Concurrency: 1, Duration: time.Second},
		streams.establish,
	)
	if err != nil || result.Errors != 0 {
		t.Fatalf("setup: %+v %v", result, err)
	}
	deadline := time.Now().Add(time.Second)
	for streams.received[0].Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if streams.received[0].Load() != uint64(len("payload")) {
		t.Fatal("setup canceled the transfer")
	}
	select {
	case <-serverDone:
		t.Fatal("setup completion closed tunnel")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	streams.completed.Wait()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("canceled tunnel remained open")
	}
}

func TestOriginUploadCounters(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var counts sync.Map
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		err = transferOrigin(conn, &counts)
		done <- errors.Join(err, conn.Close())
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "U %s\n%s", strconv.Itoa(7), "hello"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	count, ok := counts.Load("7")
	if !ok || count.(*atomic.Uint64).Load() != 5 {
		t.Fatal("upload not counted at origin")
	}
}
