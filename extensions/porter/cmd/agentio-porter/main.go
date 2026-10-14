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
	"os"
	"os/signal"
	"syscall"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/porter/pkg/processor"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("connect processor failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("agentio-porter", flag.ContinueOnError)
	grpcPort := flags.Int("grpc-port", 9002, "The gRPC port used for communicating with Envoy proxy on localhost")
	grpcHealthPort := flags.Int("grpc-health-port", 9003, "The port used for gRPC liveness and readiness probes")
	xdsAddress := flags.String("xds-address", "", "Agentiod TLS ADS endpoint")
	xdsNodeID := flags.String("xds-node-id", "", "ADS node ID; defaults to the gateway Pod identity and cluster domain")
	rootPath := flags.String("xds-root-path", "/var/run/secrets/istio/root-cert.pem", "ADS trust bundle")
	tokenPath := flags.String("xds-token-path", "/var/run/secrets/tokens/istio-token", "Pod-bound ADS token")
	clusterID := flags.String("cluster-id", "Kubernetes", "Cluster ID used by Agentiod Workload resources")
	clusterDomain := flags.String("cluster-domain", "cluster.local", "Cluster DNS domain used in the ADS node ID")
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
	if *timeout <= 0 || *clusterID == "" || *clusterDomain == "" {
		return fmt.Errorf("positive timeout, cluster ID and cluster domain are required")
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
			slog.Error("close ADS connection", "error", err)
		}
	}()
	id := *xdsNodeID
	if id == "" {
		id = fmt.Sprintf("waypoint~%s~%s.%s~%s.svc.%s",
			os.Getenv("POD_IP"), name, namespace, namespace, *clusterDomain)
	}
	client, err := xdsclient.New(conn, xdsclient.Config{
		Node: &core.Node{
			Id:       id,
			Metadata: metadata,
		},
		Watches: processor.Watches(),
	})
	if err != nil {
		return err
	}
	var source processor.DemandSource = client
	group, ctx := errgroup.WithContext(ctx)
	if cacheConfig.IdleTTL > 0 || cacheConfig.MaxEntries > 0 {
		cache, err := demandcache.New(xdsSource{client: client}, cacheConfig)
		if err != nil {
			return err
		}
		source = cache
		group.Go(func() error { return cache.Run(ctx) })
	}
	group.Go(func() error {
		return serve(ctx, fmt.Sprintf("127.0.0.1:%d", *grpcPort), fmt.Sprintf(":%d", *grpcHealthPort),
			client, processor.NewPolicyHandler(source, *clusterID), *timeout)
	})
	return group.Wait()
}

func serve(
	ctx context.Context,
	address, healthAddress string,
	client *xdsclient.Client,
	handler processor.Handler,
	timeout time.Duration,
) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(server, &processor.Server{Handler: handler, Timeout: timeout})
	healthListener, err := net.Listen("tcp", healthAddress)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	healthServer := grpc.NewServer()
	health := grpchealth.NewServer()
	health.SetServingStatus("liveness", healthpb.HealthCheckResponse_SERVING)
	updateReadiness := func() <-chan struct{} {
		changed, ready := client.Observe(model.WorkloadType, model.SandboxType)
		state := healthpb.HealthCheckResponse_NOT_SERVING
		if ready {
			state = healthpb.HealthCheckResponse_SERVING
		}
		for _, service := range []string{"", "readiness", extproc.ExternalProcessor_ServiceDesc.ServiceName} {
			health.SetServingStatus(service, state)
		}
		return changed
	}
	changed := updateReadiness()
	healthpb.RegisterHealthServer(healthServer, health)
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return client.Run(ctx) })
	group.Go(func() error { return server.Serve(listener) })
	group.Go(func() error { return healthServer.Serve(healthListener) })
	group.Go(func() error {
		for {
			select {
			case <-ctx.Done():
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
