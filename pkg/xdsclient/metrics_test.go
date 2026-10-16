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

package xdsclient

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestOptionalMetricsRegistration(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	cfg := Config{Node: &core.Node{Id: "test"}, Watches: []Watch{{TypeURL: testType}}}
	c, err := New(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.metrics != nil {
		t.Fatal("metrics enabled without a registerer")
	}
	registry := prometheus.NewRegistry()
	cfg.MetricsRegisterer = registry
	if _, err := New(conn, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := New(conn, cfg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	shared := prometheus.NewRegistry()
	for _, name := range []string{"first", "second"} {
		cfg.MetricsRegisterer = prometheus.WrapRegistererWith(prometheus.Labels{"client": name}, shared)
		if _, err := New(conn, cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDemandWaitMetrics(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	synctest.Test(t, func(t *testing.T) {
		registry := prometheus.NewRegistry()
		c, err := New(conn, Config{
			Node:              &core.Node{Id: "test"},
			Watches:           []Watch{{TypeURL: testType}},
			MetricsRegisterer: registry,
		})
		if err != nil {
			t.Fatal(err)
		}
		waiters := c.metrics.waiters.WithLabelValues(testType)
		first := beginDemand(t.Context(), c, "a")
		lease := acquire(t, c, "a")
		defer lease.Release()
		second := make(chan error, 1)
		go func() {
			_, err := lease.Demand(t.Context())
			second <- err
		}()
		synctest.Wait()
		if testutil.ToFloat64(waiters) != 2 {
			t.Fatal("shared resource must count both waiting calls")
		}
		time.Sleep(time.Second)
		// A reconnect must not clear waiters or restart their timers.
		c.reset()
		synctest.Wait()
		if testutil.ToFloat64(waiters) != 2 {
			t.Fatal("reconnect changed waiter count")
		}
		time.Sleep(time.Second)
		publishString(t, c, "a", "ready")
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		if err := <-second; err != nil {
			t.Fatal(err)
		}
		if _, err := lease.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}

		for _, result := range []string{"canceled", "timeout", "not_found", "error"} {
			pending := acquire(t, c, result)
			ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
			if result == "timeout" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), time.Second)
			}
			done := make(chan error, 1)
			go func() {
				_, err := pending.Demand(ctx)
				done <- err
			}()
			synctest.Wait()
			if testutil.ToFloat64(waiters) != 1 {
				t.Fatal("missing waiter")
			}
			time.Sleep(time.Second)
			var expected error
			switch result {
			case "canceled":
				cancel()
				expected = context.Canceled
			case "timeout":
				expected = context.DeadlineExceeded
			case "not_found":
				removeNames(t, c, result)
				expected = ErrNotFound
			case "error":
				pending.Release()
				expected = ErrReleased
			}
			if err := <-done; !errors.Is(err, expected) {
				t.Fatalf("%s: %v", result, err)
			}
			cancel()
			pending.Release()
		}
		if testutil.ToFloat64(waiters) != 0 {
			t.Fatal("waiters leaked")
		}
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		samples := 0
		for _, family := range families {
			if family.GetName() != "agentio_xds_client_demand_wait_duration_seconds" {
				continue
			}
			for _, sample := range family.Metric {
				labels := map[string]string{}
				for _, label := range sample.Label {
					labels[label.GetName()] = label.GetValue()
				}
				count, sum := uint64(1), 1.0
				if labels["result"] == "success" {
					count, sum = 2, 4
				}
				if labels["resource_type"] != testType || len(labels) != 2 {
					t.Fatalf("labels: %v", labels)
				}
				if sample.GetHistogram().GetSampleCount() != count || sample.GetHistogram().GetSampleSum() != sum {
					t.Fatalf("incorrect wait duration or immediate hit recorded: %v", sample)
				}
				samples++
			}
		}
		if samples != 5 {
			t.Fatalf("result series: %d", samples)
		}
	})
}
