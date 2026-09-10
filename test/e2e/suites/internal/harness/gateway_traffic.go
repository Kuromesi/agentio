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

package harness

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
)

// RunGatewayTraffic is shared by the Envoy and agentgateway suites. Proofs must
// establish traversal; origin success alone can be a direct bypass.
func RunGatewayTraffic(t *testing.T, src, dst echo.Instance, proof, grpcProof echo.Checker, verifyGRPC func(*testing.T, string, string)) {
	t.Run("http traffic", func(t *testing.T) {
		options := dst.CallOptionsOrFail(t, "http")
		options.Count = 1
		// Make the first short-lived request the convergence gate for the
		// protocols below. An origin-only success can still be a direct call
		// while the new egress policy is propagating to the data plane.
		options.Check = check.And(check.OK(), proof)
		options.Retry = FixedRetry(2*time.Minute, 5*time.Second)
		src.CallOrFail(t, options)
	})

	t.Run("tcp traffic", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.TCP,
			Address:  dst.Address(),
			Port:     9091,
			Count:    1,
			Check:    check.OK(),
			Retry:    FixedRetry(2*time.Minute, 5*time.Second),
		})
	})

	t.Run("https traffic", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTPS,
			Address:  dst.Address(),
			Port:     443,
			Count:    1,
			Check:    check.OK(),
			Retry:    FixedRetry(2*time.Minute, 5*time.Second),
		})
	})

	t.Run("grpc connection remains open and traverses gateway", func(t *testing.T) {
		// The catch-all DFP path derives the upstream port from :authority.
		// Carry the service port so the request reaches the gRPC workload port.
		authority := net.JoinHostPort(dst.Address(), "7070")
		requestID := fmt.Sprintf("agentio-e2e-grpc-%d", time.Now().UnixNano())
		started := time.Now()
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.GRPC,
			Address:  dst.Address(),
			Port:     7070,
			// Istio's echo client reuses one gRPC connection by default. Pacing 21
			// unary RPCs at one per second holds the same HTTP/2 connection open
			// beyond Envoy's 15-second default request timeout. Every successful
			// unary response also requires its final gRPC status trailer to arrive.
			Count:   21,
			QPS:     1,
			Timeout: 35 * time.Second,
			Headers: map[string]string{
				"Host":         authority,
				"X-Request-Id": requestID,
			},
			Check: check.And(
				check.OK(),
				check.RequestHeader("X-Request-Id", requestID),
				grpcProof,
			),
			Retry: FixedRetry(45*time.Second, time.Second),
		})
		if elapsed := time.Since(started); elapsed < 20*time.Second {
			t.Fatalf("paced gRPC connection lasted %s, want at least 20s", elapsed)
		}

		// A successful origin response alone could come from direct traffic.
		// The request ID in the gateway's structured access log proves that
		// this exact gRPC request traversed the egress gateway.
		if verifyGRPC != nil {
			verifyGRPC(t, requestID, authority)
		}
	})

	// h2c sits on a separate branch in waypoint's HTTPInspector path from
	// HTTP/1.1; without an explicit case the protocol matcher could misroute
	// upgraded connections into forward-tcp.
	t.Run("http2 (h2c) traffic", func(t *testing.T) {
		// The service port must be present in :authority or the DFP path
		// resolves the scheme default (80) instead of 85.
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP2,
			Address:  dst.Address(),
			Port:     85,
			Count:    1,
			Headers: map[string]string{
				"Host": net.JoinHostPort(dst.Address(), "85"),
			},
			Check: check.OK(),
			Retry: FixedRetry(2*time.Minute, 5*time.Second),
		})
	})
}

// RunGatewayExtProc reuses the fixture's request and response mutation contract.
func RunGatewayExtProc(t *testing.T, src, dst echo.Instance) {
	options := dst.CallOptionsOrFail(t, "http")
	options.Count = 1
	options.Check = check.And(check.OK(), check.RequestHeader("X-Hello-To-Ext-Proc", "true"), check.ResponseHeader("X-Hello-From-Ext-Proc", "true"))
	options.Retry = FixedRetry(2*time.Minute, 5*time.Second)
	src.CallOrFail(t, options)
}

func RunGatewayMatchPorts(t *testing.T, src, dst echo.Instance, through, bypass echo.Checker) {
	for _, tc := range []struct {
		name, port string
		proof      echo.Checker
	}{
		{"matched port traverses gateway", "http", through},
		{"unmatched port bypasses gateway", "http2", bypass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := dst.CallOptionsOrFail(t, tc.port)
			options.Count = 1
			options.Check = check.And(check.OK(), tc.proof)
			options.Retry = FixedRetry(2*time.Minute, 5*time.Second)
			src.CallOrFail(t, options)
		})
	}
}
