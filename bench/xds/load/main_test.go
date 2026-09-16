// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/openkruise/agentio/bench/xds/scenario"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadinessTimeoutCountsFailure(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.Certificate()
	certServer.Close() // closed endpoint: cannot become ready
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := config{target: certServer.Listener.Addr().String(), caFile: ca, tokenFile: token, scenario: "discovery", scenarioConfig: `{"types":["example.Resource"]}`, podName: "pod", namespace: "ns", podUID: "uid", nodeName: "node", podIP: "127.0.0.1", maxConnections: 1, readyTimeout: 50 * time.Millisecond}
	b, err := newBench(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	b.wg.Add(1)
	go b.run(0)
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness deadline did not release client")
	}
	if b.failures.Load() != 1 || b.ready.Load() != 0 || b.connected.Load() != 0 {
		t.Fatalf("incorrect timeout accounting: failures=%d ready=%d connected=%d", b.failures.Load(), b.ready.Load(), b.connected.Load())
	}
}

// The management API delegates opaque parameters without knowing a scenario name.
func TestRoundUsesRegisteredFactoryAndIsolatesEpochs(t *testing.T) {
	b := &bench{target: 1, samples: map[int]sample{0: {ID: 0}}, factory: scenario.ClientFactory{
		PrepareRound: func(raw json.RawMessage) (any, error) {
			var expected struct {
				Revision string `json:"revision"`
			}
			err := scenario.Decode(raw, &expected)
			return expected.Revision, err
		},
	}}
	b.ready.Store(1)
	handler := b.handler()
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"id":1,"parameters":{"revision":"first"}}`, http.StatusOK},
		{`{"id":1,"parameters":{"revision":"old"}}`, http.StatusConflict},
		{`{"id":2,"parameters":{"misspelled":true}}`, http.StatusBadRequest},
		{`{"id":2,"parameters":{"revision":"second"}}`, http.StatusOK},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/round", strings.NewReader(test.body)))
		if w.Code != test.status {
			t.Fatalf("%s: got %d: %s", test.body, w.Code, w.Body)
		}
	}
	if b.expected != "second" || b.round.ID != 2 || len(b.samples) != 0 {
		t.Fatalf("round state: %+v expected=%v samples=%v", b.round, b.expected, b.samples)
	}
}
