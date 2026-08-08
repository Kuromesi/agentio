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
	"errors"
	"net"
	"net/http"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// httpShutdownTimeout bounds the graceful drain window on context cancellation.
	httpShutdownTimeout = 5 * time.Second

	// The timeouts below bound how long a single client connection may hold
	// server resources, closing the Slowloris class of slow-request attacks
	// (gosec G112). The admin server can be bound to all interfaces, so these
	// apply even to the otherwise-trusted debug endpoints.
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 60 * time.Second
)

// HTTPServer converts the given HTTP handler into a Runnable that listens
// on addr. The server name is used for logging purposes. On context
// cancellation the server is drained via Shutdown within httpShutdownTimeout.
func HTTPServer(name string, handler http.Handler, addr string) Runnable {
	return Func(func(ctx context.Context) error {
		log := ctrllog.Log.WithValues("name", name)
		log.Info("HTTP server starting")

		lis, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error(err, "HTTP server failed to listen")
			return err
		}

		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: httpReadHeaderTimeout,
			ReadTimeout:       httpReadTimeout,
			WriteTimeout:      httpWriteTimeout,
			IdleTimeout:       httpIdleTimeout,
		}

		log.Info("HTTP server listening", "addr", lis.Addr().String())

		// Terminate the server on context cancellation. The done channel
		// guarantees the goroutine does not leak after Serve returns.
		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			select {
			case <-ctx.Done():
				log.Info("HTTP server shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
				defer cancel()
				if err := srv.Shutdown(shutdownCtx); err != nil {
					log.Error(err, "HTTP server graceful shutdown failed")
				}
			case <-doneCh:
			}
		}()

		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(err, "HTTP server failed")
			return err
		}
		log.Info("HTTP server terminated")
		return nil
	})
}
