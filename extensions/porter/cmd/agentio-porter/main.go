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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/structpb"

	"istio.io/istio/pkg/env"

	"github.com/openkruise/agentio/extensions/porter/pkg/processor"
	"github.com/openkruise/agentio/pkg/demandcache"
	agentiolog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

var (
	log      = agentiolog.New("porter")
	logLevel = env.Register(
		"AGENTIO_LOG_LEVEL",
		"info",
		"Minimum Porter log level: debug, info, warn, error, or none.",
	)
	logFormat = env.Register("AGENTIO_LOG_FORMAT", "text", "Porter log encoding: text or json.")
)

// xdsSource adapts concrete xDS subscriptions to the cache's lease interface.
// It lives at the composition boundary so neither package depends on the other.
type xdsSource struct {
	client *xdsclient.Client
}

func (s xdsSource) Acquire(typ, name string) (demandcache.Lease[*xdsclient.Resource], error) {
	return s.client.Acquire(typ, name)
}

func main() {
	// Keep initialization failures out of the dependency's standard-log wrapper.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Error("Porter failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	logger, err := agentiolog.NewLogger(os.Stderr, logLevel.Get(), logFormat.Get())
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	flags := flag.NewFlagSet("agentio-porter", flag.ContinueOnError)
	metricsPort := flags.Int("metrics-port", 9004, "HTTP port exposing Prometheus metrics independently of the gateway")
	grpcPort := flags.Int("grpc-port", 9002, "The gRPC port used for communicating with Envoy proxy on localhost")
	grpcHealthPort := flags.Int("grpc-health-port", 9003, "The port used for gRPC liveness and readiness probes")
	xdsAddress := flags.String("xds-address", "", "Agentiod TLS ADS endpoint")
	domain := flags.String("domain", "", "Proxy DNS domain; defaults to <namespace>.svc.cluster.local")
	xdsNodeID := flags.String(
		"xds-node-id",
		"",
		"ADS node ID; defaults to agentio-porter~<Pod IP>~<Pod name>.<namespace>~<DNS domain>",
	)
	rootPath := flags.String("xds-root-path", "/var/run/secrets/agentio/root-cert.pem", "ADS trust bundle")
	tokenPath := flags.String("xds-token-path", "/var/run/secrets/tokens/agentio-token", "Pod-bound ADS token")
	clusterID := flags.String("cluster-id", "Kubernetes", "Cluster ID used by Agentiod Workload resources")
	timeout := flags.Duration("request-timeout", 4*time.Second, "CONNECT processing budget, including demand waits")
	cacheConfig := demandcache.Config{}
	flags.DurationVar(
		&cacheConfig.IdleTTL,
		"xds-cache-idle-ttl",
		time.Minute,
		"Release idle demand subscriptions after this duration; zero disables expiration",
	)
	flags.IntVar(
		&cacheConfig.MaxEntries,
		"xds-cache-max-entries",
		10000,
		"Total retained demand entries across resource types; zero disables LRU eviction",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := cacheConfig.Validate(); err != nil {
		return err
	}
	if *timeout <= 0 || *clusterID == "" {
		return fmt.Errorf("positive timeout and cluster ID are required")
	}
	name, namespace := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
	if name == "" || namespace == "" {
		return fmt.Errorf("POD_NAME and POD_NAMESPACE are required")
	}
	metadata, err := structpb.NewStruct(map[string]any{
		"POD_NAME":      name,
		"POD_NAMESPACE": namespace,
		"POD_UID":       os.Getenv("POD_UID"),
	})
	if err != nil {
		return err
	}
	conn, err := xdsclient.Dial(*xdsAddress, *rootPath, *tokenPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Error("close ADS connection", "error", err)
		}
	}()
	id := *xdsNodeID
	if id == "" {
		if *domain == "" {
			*domain = namespace + ".svc.cluster.local"
		}
		id = fmt.Sprintf("%s~%s~%s.%s~%s", model.ProxyTypeAgentioPorter, os.Getenv("POD_IP"), name, namespace, *domain)
	}
	registry := prometheus.NewRegistry()
	client, err := xdsclient.New(conn, xdsclient.Config{
		MetricsRegisterer: registry,
		Node: &core.Node{
			Id:       id,
			Metadata: metadata,
		},
		Watches: processor.Watches(),
	})
	if err != nil {
		return err
	}
	log.Info("starting Porter", "node_id", id, "xds_address", *xdsAddress, "cluster_id", *clusterID,
		"request_timeout", *timeout, "cache_idle_ttl", cacheConfig.IdleTTL, "cache_max_entries", cacheConfig.MaxEntries)
	var source processor.DemandSource = client
	group, ctx := errgroup.WithContext(ctx)
	cacheSize := func() int { return 0 }
	if cacheConfig.IdleTTL > 0 || cacheConfig.MaxEntries > 0 {
		cache, err := demandcache.New(xdsSource{client: client}, cacheConfig)
		if err != nil {
			return err
		}
		source = cache
		cacheSize = cache.Len
		group.Go(func() error { return cache.Run(ctx) })
	}
	connectDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agentio_porter_connect_duration_seconds",
		Help:    "CONNECT processing from received headers through response send completion.",
		Buckets: []float64{.0005, .001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2, 4, 8},
	}, []string{"protocol"})
	registry.MustRegister(connectDuration, prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "agentio_porter_demand_cache_entries",
		Help: "Retained demand-cache leases across resource types; zero when retention is disabled.",
	}, func() float64 { return float64(cacheSize()) }))
	group.Go(func() error { return serveMetrics(ctx, fmt.Sprintf(":%d", *metricsPort), registry) })
	group.Go(func() error {
		return serve(ctx, fmt.Sprintf("127.0.0.1:%d", *grpcPort), fmt.Sprintf(":%d", *grpcHealthPort),
			client, processor.NewPolicyHandler(source, *clusterID), *timeout, connectDuration)
	})
	return group.Wait()
}

func serve(
	ctx context.Context,
	address, healthAddress string,
	client *xdsclient.Client,
	handler processor.Handler,
	timeout time.Duration,
	connectDuration *prometheus.HistogramVec,
) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(
		server,
		&processor.Server{Handler: handler, Timeout: timeout, ConnectDuration: connectDuration},
	)
	healthListener, err := net.Listen("tcp", healthAddress)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	healthServer := grpc.NewServer()
	health := grpchealth.NewServer()
	health.SetServingStatus("liveness", healthpb.HealthCheckResponse_SERVING)
	lastState := healthpb.HealthCheckResponse_UNKNOWN
	updateReadiness := func() <-chan struct{} {
		changed, ready := client.Observe(model.WorkloadType, model.SandboxType)
		state := healthpb.HealthCheckResponse_NOT_SERVING
		if ready {
			state = healthpb.HealthCheckResponse_SERVING
		}
		if state != lastState {
			log.Info("Porter readiness changed", "ready", ready)
			lastState = state
		}
		for _, service := range []string{"", "readiness", extproc.ExternalProcessor_ServiceDesc.ServiceName} {
			health.SetServingStatus(service, state)
		}
		return changed
	}
	changed := updateReadiness()
	healthpb.RegisterHealthServer(healthServer, health)
	log.Info("Porter listeners started", "address", listener.Addr(), "health_address", healthListener.Addr())
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return client.Run(ctx) })
	group.Go(func() error { return server.Serve(listener) })
	group.Go(func() error { return healthServer.Serve(healthListener) })
	group.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				log.Info("stopping Porter")
				health.Shutdown()
				server.Stop()
				healthServer.Stop()
				return nil
			case <-changed:
				changed = updateReadiness()
			}
		}
	})
	return group.Wait()
}

func serveMetrics(ctx context.Context, address string, registry *prometheus.Registry) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	stop := context.AfterFunc(ctx, func() {
		if err := server.Close(); err != nil {
			log.Error("close metrics server", "error", err)
		}
	})
	defer stop()
	log.Info("Porter metrics listening", "address", listener.Addr())
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
