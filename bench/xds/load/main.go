// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// xds-load runs discovery and TrafficPolicy scenarios using fakeclient.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/openkruise/agentio/bench/xds/fakeclient"
	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario"
	"google.golang.org/protobuf/types/known/structpb"
)

type config struct {
	target, serverName, caFile, tokenFile, listen        string
	podName, namespace, podUID, nodeName, podIP, version string
	scenario, scenarioConfig                             string
	ackDelay                                             time.Duration
	readyTimeout                                         time.Duration
	maxConnections                                       int
}

func flags() config {
	var c config
	flag.StringVar(&c.scenarioConfig, "scenario-config", "{}", "scenario-specific JSON options")
	flag.StringVar(&c.scenario, "scenario", "discovery", "client scenario: discovery or trafficpolicy")
	flag.DurationVar(&c.ackDelay, "ack-delay", 0, "delay each ACK; bounds include this intentional delay")
	flag.StringVar(&c.target, "target", "", "xDS host:port (required)")
	flag.StringVar(&c.serverName, "server-name", "", "TLS server name; defaults to target hostname")
	flag.StringVar(&c.caFile, "ca-file", "/var/run/ads/ca/root-cert.pem", "server CA PEM bundle")
	flag.StringVar(&c.tokenFile, "token-file", "/var/run/ads/token", "bearer token file, read for each new stream")
	flag.StringVar(&c.listen, "listen", "127.0.0.1:8088", "management HTTP address; no authentication")
	flag.StringVar(&c.podName, "pod-name", os.Getenv("POD_NAME"), "authenticated Pod name")
	flag.StringVar(&c.namespace, "namespace", os.Getenv("POD_NAMESPACE"), "authenticated Pod namespace")
	flag.StringVar(&c.podUID, "pod-uid", os.Getenv("POD_UID"), "authenticated Pod UID")
	flag.StringVar(&c.nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name")
	flag.StringVar(&c.podIP, "pod-ip", os.Getenv("POD_IP"), "Pod IP")
	flag.StringVar(&c.version, "istio-version", "1.29", "ISTIO_VERSION client metadata")
	flag.DurationVar(&c.readyTimeout, "ready-timeout", 60*time.Second, "per-stream initial configuration deadline")
	flag.IntVar(&c.maxConnections, "max-connections", 50000, "maximum connections in this process")
	flag.Parse()
	return c
}

func (c config) validate() error {
	for name, value := range map[string]string{"target": c.target, "pod-name": c.podName, "namespace": c.namespace, "pod-uid": c.podUID, "node-name": c.nodeName, "pod-ip": c.podIP} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if _, _, err := net.SplitHostPort(c.target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if c.readyTimeout <= 0 || c.maxConnections <= 0 || c.ackDelay < 0 {
		return errors.New("ready-timeout and max-connections must be positive")
	}
	return nil
}

type round = loadapi.Round
type sample = loadapi.Sample

type bench struct {
	cfg       config
	ctx       context.Context
	tlsConfig *tls.Config
	mu        sync.Mutex
	target    int
	ramping   bool
	round     round
	expected  any
	factory   scenario.ClientFactory
	samples   map[int]sample
	errors    map[string]int

	connected       atomic.Int64
	ready           atomic.Int64
	responses       atomic.Int64
	responsesByType map[string]int64
	failures        atomic.Int64
	dials           atomic.Int64
	wg              sync.WaitGroup
}

func newBench(ctx context.Context, c config) (*bench, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.serverName == "" {
		c.serverName, _, _ = net.SplitHostPort(c.target)
	}
	factory, err := newScenario(c.scenario, json.RawMessage(c.scenarioConfig))
	if err != nil {
		return nil, err
	}
	if factory.New == nil {
		return nil, errors.New("scenario must provide a client factory")
	}
	tlsConfig, err := fakeclient.TLSFromCA(c.caFile, c.serverName)
	if err != nil {
		return nil, err
	}
	return &bench{cfg: c, ctx: ctx, samples: map[int]sample{}, errors: map[string]int{}, tlsConfig: tlsConfig, factory: factory, responsesByType: map[string]int64{}}, nil
}

func (b *bench) failure(err error) {
	b.failures.Add(1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.errors) < 20 {
		b.errors[err.Error()]++
	}
}

func (b *bench) run(id int) {
	defer b.wg.Done()
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()
	// Include connection establishment in the per-client readiness deadline.
	timer := time.AfterFunc(b.cfg.readyTimeout, cancel)
	defer timer.Stop()
	md, _ := structpb.NewStruct(map[string]any{"POD_NAME": b.cfg.podName, "POD_NAMESPACE": b.cfg.namespace, "POD_UID": b.cfg.podUID, "NODE_NAME": b.cfg.nodeName, "ISTIO_VERSION": b.cfg.version})
	node := &core.Node{Id: fmt.Sprintf("ztunnel~%s~%s-%d~%s", b.cfg.podIP, b.cfg.podName, id, b.cfg.namespace), Metadata: md}
	client, err := fakeclient.Open(ctx, fakeclient.Config{
		Target: b.cfg.target, Node: node, TLSConfig: b.tlsConfig, Token: fakeclient.FileToken(b.cfg.tokenFile),
		DialContext: func(ctx context.Context, address string) (net.Conn, error) {
			b.dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	})
	if err != nil {
		if b.ctx.Err() == nil {
			b.failure(err)
		}
		return
	}
	defer client.Close()
	b.connected.Add(1)
	defer b.connected.Add(-1)
	isReady := false
	defer func() {
		if isReady {
			b.ready.Add(-1)
		}
	}()
	observer := b.factory.New()
	for _, sub := range observer.Subscriptions() {
		if err := client.Subscribe(sub.TypeURL, sub.Names...); err != nil {
			if b.ctx.Err() == nil {
				b.failure(err)
			}
			return
		}
	}
	for {
		response, err := client.Recv()
		if err != nil {
			if b.ctx.Err() == nil {
				b.failure(fmt.Errorf("stream %d (ready=%v): %w", id, isReady, err))
			}
			return
		}
		received := time.Now().UnixNano()
		b.responses.Add(1)
		b.mu.Lock()
		activeRound, expected := b.round, b.expected
		b.responsesByType[response.TypeUrl]++
		b.mu.Unlock()
		observation, err := observer.Observe(response, expected)
		if err != nil {
			b.failure(err)
			return
		}
		if observation.Sample != nil && observation.Reply != scenario.ACK {
			b.failure(errors.New("samples require ACK submission"))
			return
		}
		if b.cfg.ackDelay > 0 {
			t := time.NewTimer(b.cfg.ackDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				if b.ctx.Err() == nil {
					b.failure(ctx.Err())
				}
				return
			case <-t.C:
			}
		}
		switch observation.Reply {
		case scenario.ACK:
			err = client.ACK(response)
		case scenario.NACK:
			err = client.NACK(response, observation.NACKReason)
		case scenario.None:
			err = nil
		default:
			err = errors.New("invalid scenario reply")
		}
		if err != nil {
			if b.ctx.Err() == nil {
				b.failure(err)
			}
			return
		}
		if s := observation.Sample; s != nil {
			s.ID = id
			s.ReceiveNS = received
			s.AckNS = time.Now().UnixNano()
			b.mu.Lock()
			if activeRound.ID != 0 && b.round.ID == activeRound.ID {
				if _, exists := b.samples[id]; !exists {
					b.samples[id] = *s
				}
			}
			b.mu.Unlock()
		}
		ready := observation.Ready
		if ready && !isReady {
			timer.Stop()
			isReady = true
			b.ready.Add(1)
		}
	}
}

func (b *bench) scale(n int, rate float64) error {
	if n < 0 || n > b.cfg.maxConnections || rate < 0.001 || rate > 100000 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return errors.New("invalid target or rate (0.001 <= rate <= 100000)")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil || b.ramping || n < b.target {
		return errors.New("cannot scale down, overlap ramps, or scale after shutdown")
	}
	start := b.target
	b.target = n
	b.ramping = true
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() { b.mu.Lock(); b.ramping = false; b.mu.Unlock() }()
		ticker := time.NewTicker(time.Duration(float64(time.Second) / rate))
		defer ticker.Stop()
		for id := start; id < n; id++ {
			select {
			case <-b.ctx.Done():
				return
			case <-ticker.C:
			}
			b.wg.Add(1)
			go b.run(id)
		}
	}()
	return nil
}

func (b *bench) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scale", func(w http.ResponseWriter, r *http.Request) {
		n, e1 := strconv.Atoi(r.URL.Query().Get("n"))
		rate, e2 := strconv.ParseFloat(r.URL.Query().Get("rate"), 64)
		if e1 != nil || e2 != nil {
			http.Error(w, "require n and rate", 400)
			return
		}
		if err := b.scale(n, rate); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]int{"target": n})
	})
	mux.HandleFunc("POST /round", func(w http.ResponseWriter, r *http.Request) {
		if b.factory.PrepareRound == nil {
			http.Error(w, "selected scenario does not support managed rounds", 400)
			return
		}
		var expected round
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&expected); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if expected.ID == 0 {
			http.Error(w, "round id must be positive", 400)
			return
		}
		prepared, err := b.factory.PrepareRound(expected.Parameters)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.target == 0 || b.ready.Load() != int64(b.target) || b.failures.Load() != 0 || expected.ID <= b.round.ID {
			http.Error(w, "require all clients ready, no failures, and increasing round id", 409)
			return
		}
		b.round = expected
		b.expected = prepared
		b.samples = map[int]sample{}
		writeJSON(w, expected)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		b.mu.Lock()
		defer b.mu.Unlock()
		var samples []sample
		if r.URL.Query().Get("samples") == "1" {
			samples = make([]sample, 0, len(b.samples))
			for _, s := range b.samples {
				samples = append(samples, s)
			}
		}
		writeJSON(w, loadapi.Status{NowNS: time.Now().UnixNano(), Target: b.target, Ramping: b.ramping,
			Connected: b.connected.Load(), Ready: b.ready.Load(), Failures: b.failures.Load(), Errors: b.errors,
			Dials: b.dials.Load(), Responses: b.responses.Load(), ResponsesByType: b.responsesByType,
			Round: b.round, Received: len(b.samples), Samples: samples, HeapAlloc: mem.HeapAlloc, Goroutines: runtime.NumGoroutine()})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	c := flags()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	b, err := newBench(ctx, c)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: c.listen, Handler: b.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	log.Printf("ADS load client listening on %s; target=%s", c.listen, c.target)
	err = server.ListenAndServe()
	cancel()
	// A scale handler that passed its context check must register before Wait.
	b.mu.Lock()
	b.mu.Unlock()
	b.wg.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
