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
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	servicev3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/klog/v2"

	"istio.io/istio/pkg/test/extproc"
)

var port = flag.Int("port", 9002, "gRPC port")

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		klog.Fatalf("failed to listen: %v", err)
	}

	server := grpc.NewServer(grpc.MaxConcurrentStreams(1000))
	servicev3.RegisterExternalProcessorServer(server, extproc.NewServer(extproc.ConfigFromEnvironment(os.Getenv)))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)

	serveError := make(chan error, 1)
	go func() {
		klog.Infof("starting ext-proc gRPC server on %s", listener.Addr())
		serveError <- server.Serve(listener)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serveError:
		if err != nil {
			klog.Fatalf("ext-proc gRPC server failed: %v", err)
		}
	case <-ctx.Done():
		healthServer.Shutdown()
		gracefulStop := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(gracefulStop)
		}()
		select {
		case <-gracefulStop:
		case <-time.After(10 * time.Second):
			server.Stop()
		}
	}
}
