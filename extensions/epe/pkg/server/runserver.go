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
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"istio.io/istio/extensions/epe/pkg/audit/accesslog"
	"istio.io/istio/extensions/epe/pkg/certs"
	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc"
	"istio.io/istio/extensions/epe/pkg/runnable"
)

// Config carries everything the ext-proc gRPC server needs. It is consumed
// once by New; a zero-value Config serves plaintext. Resolve and GrpcPort
// must at least be set.
type Config struct {
	GrpcPort int
	// Listener serves an already-bound socket and makes GrpcPort unused. It
	// lets a caller that needs to know the address up front bind it first
	// rather than reserving a port by binding and closing one, which leaves the
	// port unowned until this server binds. See runnable.WithListener.
	Listener net.Listener
	// PluginBudget bounds each evaluation phase (one ext_proc message); 0 disables.
	PluginBudget time.Duration

	// SecureServing enables TLS. When true, CertProvider supplies the
	// serving certificate (and the client CA pool for mTLS); nil falls back
	// to a self-signed certificate via certs.SelfSigned. TLSOptions is
	// passed to certs.ServerTLSConfig (e.g. certs.WithClientAuth,
	// certs.WithPeerVerifier).
	SecureServing bool
	CertProvider  certs.Provider
	TLSOptions    []certs.Option

	// Resolve maps request identity to the policy units the engine evaluates.
	// Required. Policy-specific stores and binders are assembled by the caller.
	Resolve engine.Resolver
	// Registrations is the action order applied inside every rule.
	Registrations []filter.Registration
	// StreamLoggers are invoked once per stream at stream end (audit).
	StreamLoggers []filter.StreamLogger
	// AuditLogger is the per-request audit sink. nil is replaced with a
	// no-op logger inside extproc.NewServer.
	AuditLogger accesslog.Logger
}

// New assembles the ext-proc gRPC server as a runnable: TLS setup (when
// enabled), handler construction, and listener lifecycle. Configuration
// errors surface when the runnable starts.
func New(cfg Config, logger logr.Logger) runnable.Runnable {
	return runnable.Func(func(ctx context.Context) error {
		if cfg.Resolve == nil {
			return fmt.Errorf("ext-proc server config: Resolve is required")
		}

		var srv *grpc.Server
		if cfg.SecureServing {
			provider := cfg.CertProvider
			if provider == nil {
				selfSigned, err := certs.SelfSigned()
				if err != nil {
					logger.Error(err, "Failed to create self signed certificate")
					return err
				}
				provider = selfSigned
			}
			tlsConfig, err := certs.ServerTLSConfig(provider, cfg.TLSOptions...)
			if err != nil {
				logger.Error(err, "Failed to build server TLS config")
				return err
			}
			srv = grpc.NewServer(
				grpc.Creds(credentials.NewTLS(tlsConfig)),
				grpc.StreamInterceptor(recoverStreamPanic),
			)
		} else {
			srv = grpc.NewServer(grpc.StreamInterceptor(recoverStreamPanic))
		}

		extProcPb.RegisterExternalProcessorServer(
			srv,
			extproc.NewServer(extproc.ServerDeps{
				Resolve:       cfg.Resolve,
				Registrations: cfg.Registrations,
				StreamLoggers: cfg.StreamLoggers,
				AuditLogger:   cfg.AuditLogger,
				PluginBudget:  cfg.PluginBudget,
			}),
		)

		return runnable.GRPCServer("ext-proc", srv, cfg.GrpcPort,
			runnable.WithListener(cfg.Listener)).Start(ctx)
	})
}
