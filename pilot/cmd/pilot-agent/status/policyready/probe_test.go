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

package policyready

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// fakeAdmin stands in for the Envoy admin endpoint and counts scrapes so the
// latch can be observed.
type fakeAdmin struct {
	server *httptest.Server
	body   string
	calls  int
}

func newFakeAdmin(t *testing.T, body string) *fakeAdmin {
	t.Helper()
	admin := &fakeAdmin{body: body}
	admin.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		admin.calls++
		fmt.Fprint(w, admin.body)
	}))
	t.Cleanup(admin.server.Close)
	return admin
}

// probe builds a Probe pointed at the fake admin.
func (f *fakeAdmin) probe(t *testing.T) *Probe {
	t.Helper()
	host, port, err := net.SplitHostPort(f.server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split fake admin address: %v", err)
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatalf("parse fake admin port: %v", err)
	}
	return &Probe{localHostAddr: host, adminPort: uint16(parsed)}
}

func TestCheckSynced(t *testing.T) {
	admin := newFakeAdmin(t, "policy_store.initial_sync_ready: 1\n")
	if err := admin.probe(t).Check(); err != nil {
		t.Fatalf("expected ready, got %v", err)
	}
}

func TestCheckNotSynced(t *testing.T) {
	admin := newFakeAdmin(t, "policy_store.initial_sync_ready: 0\n")
	err := admin.probe(t).Check()
	if err == nil {
		t.Fatal("expected an error while the store is unsynced")
	}
}

// Absence must not read as synced: it means the extension is missing, or the
// bootstrap stats inclusion list does not admit the policy_store scope.
func TestCheckStatAbsent(t *testing.T) {
	admin := newFakeAdmin(t, "server.state: 0\n")
	if err := admin.probe(t).Check(); err == nil {
		t.Fatal("expected an error when the stat is absent")
	}
}

func TestCheckLatches(t *testing.T) {
	admin := newFakeAdmin(t, "policy_store.initial_sync_ready: 1\n")
	probe := admin.probe(t)
	if err := probe.Check(); err != nil {
		t.Fatalf("first check: %v", err)
	}
	// Flip the backing value; a latched probe must not observe it.
	admin.body = "policy_store.initial_sync_ready: 0\n"
	if err := probe.Check(); err != nil {
		t.Fatalf("second check should stay ready, got %v", err)
	}
	if admin.calls != 1 {
		t.Fatalf("expected 1 scrape after latching, got %d", admin.calls)
	}
}

func TestParseGaugeIgnoresOtherPolicyStoreStats(t *testing.T) {
	body := "policy_store.ready: 1\npolicy_store.pending_bindings: 0\npolicy_store.initial_sync_ready: 1\n"
	value, err := parseGauge(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != 1 {
		t.Fatalf("expected the gauge value 1, got %d", value)
	}
}

func TestParseGaugeRejectsOldReadyGaugeAlone(t *testing.T) {
	if _, err := parseGauge("policy_store.ready: 1\n"); err == nil {
		t.Fatal("expected an error: the old ready gauge is not the initial sync gauge")
	}
}

func TestParseGaugeTrailingLineWithoutNewline(t *testing.T) {
	value, err := parseGauge("policy_store.initial_sync_ready: 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != 1 {
		t.Fatalf("expected 1, got %d", value)
	}
}

func TestParseGaugeMalformedValue(t *testing.T) {
	if _, err := parseGauge("policy_store.initial_sync_ready: not-a-number\n"); err == nil {
		t.Fatal("expected an error for a non-numeric gauge value")
	}
}
