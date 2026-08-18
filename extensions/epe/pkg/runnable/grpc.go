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
package runnable

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultGracefulStopTimeout bounds how long a shutdown waits for in-flight
// RPCs before the server is stopped hard.
const DefaultGracefulStopTimeout = 30 * time.Second

// GRPCOption configures a gRPC runnable.
type GRPCOption func(*grpcOptions)

type grpcOptions struct {
	gracefulStopTimeout time.Duration
	listener            net.Listener
}

// WithListener serves an already-bound listener instead of binding the port
// itself, and makes the port argument unused.
//
// It exists because the alternative — asking the OS for a free port by binding
// and immediately closing it — leaves that port unowned until this runnable
// binds, a window that spans TLS config construction and server registration.
// Anything else on the machine can take it in between, and the caller then dials
// an impostor: the observed symptom is an unexplained connection reset rather
// than the address conflict it really is. Handing over a listener that was never
// released closes the window entirely.
//
// Ownership transfers: Serve closes the listener when it returns.
func WithListener(l net.Listener) GRPCOption {
	return func(o *grpcOptions) {
		if l != nil {
			o.listener = l
		}
	}
}

// WithGracefulStopTimeout overrides DefaultGracefulStopTimeout. A
// non-positive value restores the default.
func WithGracefulStopTimeout(d time.Duration) GRPCOption {
	return func(o *grpcOptions) {
		if d > 0 {
			o.gracefulStopTimeout = d
		}
	}
}

// GRPCServer converts the given gRPC server into a runnable.
// The server name is used for logging purposes.
func GRPCServer(name string, srv *grpc.Server, port int, opts ...GRPCOption) Runnable {
	cfg := grpcOptions{gracefulStopTimeout: DefaultGracefulStopTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	return Func(func(ctx context.Context) error {
		log := ctrllog.Log.WithValues("name", name)
		log.Info("gRPC server starting")

		lis := cfg.listener
		if lis == nil {
			var err error
			lis, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				log.Error(err, "gRPC server failed to listen")
				return err
			}
		}

		log.Info("gRPC server listening", "address", lis.Addr().String())

		// Terminate the server on context cancellation. The done channel
		// guarantees the goroutine does not leak after Serve returns.
		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			select {
			case <-ctx.Done():
				log.Info("gRPC server shutting down", "gracePeriod", cfg.gracefulStopTimeout)
				stopGracefully(log, srv, cfg.gracefulStopTimeout)
			case <-doneCh:
			}
		}()

		if err := srv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			log.Error(err, "gRPC server failed")
			return err
		}
		log.Info("gRPC server terminated")
		return nil
	})
}

// stopGracefully drains in-flight RPCs, then stops hard once the grace
// period expires.
//
// GracefulStop blocks until every active handler returns, and it does not
// cancel their streams — it only sends GOAWAY. A long-lived server stream
// parked in Recv() waiting on a quiet peer therefore never releases it. With
// no bound, shutdown hangs until the platform SIGKILLs the process, which
// kills the audit worker pools mid-flush; a hard Stop at least lets the
// process exit on its own terms.
func stopGracefully(log logr.Logger, srv *grpc.Server, grace time.Duration) {
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		log.Info("graceful stop exceeded its deadline; stopping hard", "gracePeriod", grace)
		// Unblocks the GracefulStop above, so its goroutine does not leak.
		srv.Stop()
		<-stopped
	}
}
