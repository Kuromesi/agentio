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

package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCalloutProtocols(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		tls      bool
		h2       bool
		want     int
	}{
		{"h1", "HTTP1", false, false, 1}, {"h2c", "HTTP2", false, true, 2},
		{"auto-cleartext", "AUTO", false, true, 1},
		{"forced-h2c-mismatch", "HTTP2", false, false, 0},
		{"auto-tls-h2", "AUTO", true, true, 2}, {"auto-tls-h1", "AUTO", true, false, 1},
		{"forced-tls-h2", "HTTP2", true, true, 2}, {"forced-h1", "HTTP1", true, true, 1},
		{"forced-h2-mismatch", "HTTP2", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
			)
			server.EnableHTTP2 = tc.h2
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetHTTP1(true)
			server.Config.Protocols.SetHTTP2(tc.h2)
			server.Config.Protocols.SetUnencryptedHTTP2(tc.h2)
			if tc.tls {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := NewCallout(
				CalloutOptions{
					Options:              DefaultOptions(),
					Protocol:             tc.protocol,
					MaxConcurrentStreams: 4,
					TLS:                  &tls.Config{InsecureSkipVerify: true},
				},
			)
			client.Timeout = time.Second
			defer client.Transport.(*calloutPool).Retire()
			for range 3 {
				resp, err := client.Get(server.URL)
				if tc.want == 0 {
					if err == nil {
						if err := resp.Body.Close(); err != nil {
							t.Error(err)
						}
						t.Fatal("expected protocol mismatch")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					t.Error(err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
				if resp.ProtoMajor != tc.want {
					t.Fatalf("protocol=%s", resp.Proto)
				}
			}
		})
	}
}

func TestCalloutColdStreamsAndRetirement(t *testing.T) {
	for _, tc := range []struct {
		limit int
		tls   bool
	}{{1, false}, {4, false}, {32, false}, {32, true}} {
		limit := tc.limit
		t.Run(fmt.Sprintf("limit%d-tls%t", limit, tc.tls), func(t *testing.T) {
			var refused, opened, closed atomic.Int64
			var mu sync.Mutex
			active := map[string]int{}
			peak := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				active[r.RemoteAddr]++
				peak = max(peak, active[r.RemoteAddr])
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				mu.Lock()
				active[r.RemoteAddr]--
				mu.Unlock()
				if _, err := w.Write([]byte("ok")); err != nil {
					t.Error(err)
				}
			}))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Config.Protocols.SetHTTP1(true)
			server.Config.Protocols.SetHTTP2(true)
			server.Config.HTTP2 = &http.HTTP2Config{
				MaxConcurrentStreams: 4,
				CountError: func(kind string) {
					if kind == "stream_REFUSED_STREAM_over_max_streams_race" {
						refused.Add(1)
					}
				},
			}
			server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					opened.Add(1)
				}
				if s == http.StateClosed {
					closed.Add(1)
				}
			}
			if tc.tls {
				server.EnableHTTP2 = true
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			opts := DefaultOptions()
			opts.MaxConnsPerHost = 3
			protocol := "HTTP2"
			if tc.tls {
				protocol = "AUTO"
			}
			client := NewCallout(
				CalloutOptions{
					Options:              opts,
					Protocol:             protocol,
					MaxConcurrentStreams: limit,
					TLS:                  &tls.Config{InsecureSkipVerify: true},
				},
			)
			client.Timeout = 3 * time.Second
			pool := client.Transport.(*calloutPool)
			defer pool.Retire()
			var wg sync.WaitGroup
			for range 96 {
				wg.Go(func() {
					resp, err := client.Get(server.URL)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						t.Error(err)
					}
					if err := resp.Body.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			if refused.Load() != 0 {
				t.Fatalf("cold start refused %d streams", refused.Load())
			}
			if peak > min(limit, 4) {
				t.Fatalf("per-connection peak %d exceeds limit", peak)
			}
			if opened.Load() > 3 {
				t.Fatalf("opened %d connections", opened.Load())
			}
			pool.Retire()
			deadline := time.Now().Add(time.Second)
			for closed.Load() != opened.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if closed.Load() != opened.Load() {
				t.Fatalf("connections leaked: open=%d closed=%d", opened.Load(), closed.Load())
			}
		})
	}
}

func TestCalloutRetireActiveResponse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		<-release
		if _, err := w.Write([]byte("done")); err != nil {
			t.Error(err)
		}
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	client := NewCallout(CalloutOptions{Options: DefaultOptions(), Protocol: "HTTP2", MaxConcurrentStreams: 4})
	client.Timeout = 2 * time.Second
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	pool := client.Transport.(*calloutPool)
	pool.Retire()
	close(release)
	body, err := io.ReadAll(resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Error(err)
	}
	if err != nil || string(body) != "done" {
		t.Fatalf("retirement interrupted response: %s %v", body, err)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.members) != 0 {
		t.Fatal("old pool retained connection")
	}
}

func TestCalloutQueuedDeadline(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxConnsPerHost = 1
	pool := NewCallout(CalloutOptions{Options: opts, Protocol: "HTTP2", MaxConcurrentStreams: 1}).Transport.(*calloutPool)
	_, err := pool.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = pool.acquire(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue error=%v", err)
	}
}

// A sustained backlog must not let newer requests starve earlier waiters.
func TestCalloutSaturatedPool(t *testing.T) {
	for _, protocol := range []string{"HTTP1", "HTTP2"} {
		t.Run(protocol, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(5 * time.Millisecond)
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetHTTP1(true)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Start()
			defer server.Close()
			opts := DefaultOptions()
			opts.MaxConnsPerHost = 4
			client := NewCallout(CalloutOptions{Options: opts, Protocol: protocol, MaxConcurrentStreams: 1})
			client.Timeout = 500 * time.Millisecond
			defer client.Transport.(*calloutPool).Retire()
			var wg sync.WaitGroup
			for range 64 {
				wg.Go(func() {
					for range 8 {
						resp, err := client.Get(server.URL)
						if err != nil {
							t.Error(err)
							return
						}
						if err := resp.Body.Close(); err != nil {
							t.Error(err)
						}
					}
				})
			}
			wg.Wait()
		})
	}
}

func TestCalloutIdleConnectionPolicy(t *testing.T) {
	for _, protocol := range []string{"HTTP1", "HTTP2"} {
		for _, idle := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s-idle%d", protocol, idle), func(t *testing.T) {
				var closed atomic.Int64
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				server.Config.Protocols = new(http.Protocols)
				server.Config.Protocols.SetHTTP1(true)
				server.Config.Protocols.SetUnencryptedHTTP2(true)
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed.Add(1)
					}
				}
				server.Start()
				defer server.Close()
				opts := DefaultOptions()
				opts.MaxIdleConnsPerHost = idle
				opts.IdleConnTimeout = 30 * time.Millisecond
				client := NewCallout(CalloutOptions{Options: opts, Protocol: protocol, MaxConcurrentStreams: 4})
				defer client.Transport.(*calloutPool).Retire()
				resp, err := client.Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(time.Second)
				for closed.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if closed.Load() != 1 {
					t.Fatal("idle connection was not closed")
				}
			})
		}
	}
}
