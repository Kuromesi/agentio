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

package callout

import (
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
	calloutfixture "github.com/openkruise/agentio/test/fixtures/httpcallout"
)

var calloutHTTP2 = flag.Bool(
	"callout-http2",
	false,
	"configure production HTTP/2 and assert the callout protocol",
)

var calloutMaxConnections = flag.Uint("callout-max-connections", 0, "EPE connection limit (0 uses protocol default)")

var calloutMaxIdle = flag.Int("callout-max-idle", -1, "EPE idle connection limit (-1 uses protocol default)")

var calloutTimeout = flag.String("callout-timeout", "2s", "successful provider timeout (empty uses production default)")

var calloutClientStreams = flag.Uint("callout-client-streams", 32, "EPE per-connection stream limit")

var calloutMaxStreams = flag.Int(
	"callout-max-streams",
	0,
	"endpoint HTTP/2 concurrent stream limit (0 uses Go default)",
)

var calloutResponseDelay = flag.Duration("callout-response-delay", 0, "delay successful continue decisions")

var calloutConnectionWindow = flag.Int(
	"callout-connection-window",
	0,
	"endpoint HTTP/2 connection receive window in bytes",
)

type transportStats struct {
	Connections       int64 `json:"connections"`
	HTTP1             int64 `json:"http1_requests"`
	HTTP2             int64 `json:"http2_requests"`
	PeakPerConnection int64 `json:"peak_handlers_per_connection"`
	PeakHandlers      int64 `json:"peak_handlers_total"`
	OpenConnections   int64 `json:"open_connections"`
	PeakConnections   int64 `json:"peak_connections"`
	RefusedStreams    int64 `json:"refused_streams"`
}

func recordPeak(peak *atomic.Int64, n int64) {
	for previous := peak.Load(); n > previous; previous = peak.Load() {
		if peak.CompareAndSwap(previous, n) {
			return
		}
	}
}

func newCalloutEndpoint(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	var connections, http1, http2 atomic.Int64
	var peak atomic.Int64
	var activeTotal, peakTotal, openConnections, peakConnections atomic.Int64
	var refusedStreams atomic.Int64
	var peers sync.Map
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/transport-stats" {
			if err := json.NewEncoder(w).
				Encode(transportStats{Connections: connections.Load(), HTTP1: http1.Load(), HTTP2: http2.Load(), PeakPerConnection: peak.Load(), PeakHandlers: peakTotal.Load(), OpenConnections: openConnections.Load(), PeakConnections: peakConnections.Load(), RefusedStreams: refusedStreams.Load()}); err != nil {
				t.Logf("transport stats: %v", err)
			}
			return
		}
		if r.Method == http.MethodPost {
			want := 1
			if *calloutHTTP2 {
				want = 2
			}
			if r.ProtoMajor != want {
				t.Errorf("callout protocol = %s, want HTTP/%d", r.Proto, want)
			}
			counter, loaded := peers.LoadOrStore(r.RemoteAddr, new(atomic.Int64))
			if !loaded {
				connections.Add(1)
				recordPeak(&peakConnections, openConnections.Add(1))
			}
			active := counter.(*atomic.Int64)
			n := active.Add(1)
			defer active.Add(-1)
			recordPeak(&peak, n)
			recordPeak(&peakTotal, activeTotal.Add(1))
			defer activeTotal.Add(-1)
			if r.ProtoMajor == 2 {
				http2.Add(1)
			} else {
				http1.Add(1)
			}
		}
		handler.ServeHTTP(w, r)
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Config.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams:          *calloutMaxStreams,
		MaxReceiveBufferPerConnection: *calloutConnectionWindow,
		CountError: func(kind string) {
			if kind == "stream_REFUSED_STREAM_over_max_streams_race" {
				refusedStreams.Add(1)
			} else {
				t.Logf("HTTP/2 error: %s", kind)
			}
		},
	}
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			if _, loaded := peers.LoadAndDelete(conn.RemoteAddr().String()); loaded {
				openConnections.Add(-1)
			}
		}
	}
	server.Start()
	return server
}

func (f *fixture) transportStats(t *testing.T) transportStats {
	t.Helper()
	resp, err := f.client.Get(f.transportURL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transport stats status: %d", resp.StatusCode)
	}
	var stats transportStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	return stats
}

func TestCalloutHTTPProtocols(t *testing.T) {
	for _, mode := range []string{"http1", "h2c"} {
		t.Run(mode, func(t *testing.T) {
			previous := *calloutHTTP2
			*calloutHTTP2 = mode == "h2c"
			t.Cleanup(func() { *calloutHTTP2 = previous })
			handler := &calloutfixture.Handler{}
			completed := make(chan struct{}, 3)
			endpoint := newCalloutEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() { completed <- struct{}{} }()
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(endpoint.Close)
			protocol := "HTTP1"
			if *calloutHTTP2 {
				protocol = "HTTP2"
			}
			client := httpclient.NewCallout(
				httpclient.CalloutOptions{
					Options:              httpclient.DefaultOptions(),
					Protocol:             protocol,
					MaxConcurrentStreams: int(*calloutClientStreams),
				},
			)
			t.Cleanup(client.CloseIdleConnections)
			wantProtocol := 1
			if *calloutHTTP2 {
				wantProtocol = 2
			}
			payload := `{"version":"0.1","phase":"request","request":{"method":"POST"}}`
			for _, path := range []string{"/continue", "/reset", "/continue"} {
				resp, err := client.Post(endpoint.URL+path, "application/json", strings.NewReader(payload))
				if path == "/reset" {
					if err == nil {
						httpclient.DrainForReuse(resp)
						t.Fatal("reset returned a response")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				httpclient.DrainForReuse(resp)
				if resp.StatusCode != 200 || resp.ProtoMajor != wantProtocol {
					t.Fatalf("status=%d protocol=%s", resp.StatusCode, resp.Proto)
				}
			}
			// A reset can reach the client before the handler runs its deferred
			// accounting. Wait for all handlers, including the reset, to exit.
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			for range 3 {
				select {
				case <-completed:
				case <-timer.C:
					t.Fatal("callout handlers did not finish")
				}
			}
			if handler.Calls.Load() != 3 || handler.Active.Load() != 0 {
				t.Fatalf("calls=%d active=%d", handler.Calls.Load(), handler.Active.Load())
			}
		})
	}
}
