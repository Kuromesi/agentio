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
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	"github.com/openkruise/agentio/test/e2e/retry"
)

const (
	DataplaneModeLabel   = "agentio.kruise.io/dataplane-mode"
	DataplaneModeSidecar = "sidecar"

	ZtunnelInjectAnnotation = "inject.agentio.kruise.io/templates"
	ZtunnelInjectTemplate   = "ztunnel"

	GatewayPodSelector = "gateway.networking.k8s.io/gateway-name=egress-gateway"
	EPEPodSelector     = "app.kubernetes.io/name=agentio-epe"
)

// ClientCapabilities are the Pod capabilities client-side fixtures need for
// raw-socket protocol scenarios.
func ClientCapabilities() []corev1.Capability {
	return []corev1.Capability{"NET_ADMIN", "NET_RAW"}
}

// TrafficFixture is the shared injected echo layout used by the sandbox
// traffic domains: one generated namespace with ztunnel-injected client and
// server Pods.
type TrafficFixture struct {
	Namespace      namespace.Instance
	Client         echo.Instance
	Server         echo.Instance
	AnotherServer  echo.Instance
	WorkloadTarget echo.Instance
}

func (f *TrafficFixture) SetupNamespace() e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		instance, cleanup, err := namespace.Apply(ctx, environment, namespace.Config{Prefix: "sandbox"})
		if err != nil {
			return nil, err
		}
		f.Namespace = instance
		return cleanup, nil
	}
}

func (f *TrafficFixture) SetupEcho(name string, replicas int, capabilities []corev1.Capability) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		instance, cleanup, err := echo.Apply(ctx, environment, echo.Config{
			Name: name, Namespace: f.Namespace.Name(), Replicas: replicas,
			Image: echo.DefaultImage, Ports: echo.DefaultPorts(), CallTimeout: 90 * time.Second, Converge: 3,
			Labels: map[string]string{
				"app": name, DataplaneModeLabel: DataplaneModeSidecar,
			},
			PodAnnotations: map[string]string{
				ZtunnelInjectAnnotation: ZtunnelInjectTemplate,
			},
			Capabilities: capabilities,
		})
		if err != nil {
			return nil, err
		}
		switch name {
		case "client":
			f.Client = instance
		case "server":
			f.Server = instance
		case "another-server":
			f.AnotherServer = instance
		case "workload-target":
			f.WorkloadTarget = instance
		default:
			return nil, fmt.Errorf("unknown shared echo fixture %q", name)
		}
		return cleanup, nil
	}
}

// Verify exercises the client-to-server baseline call and the injected
// ztunnel admin surface so scenarios start from a proven-good fixture.
func (f *TrafficFixture) Verify(ctx context.Context) error {
	options, err := f.Server.CallOptions("http")
	if err != nil {
		return err
	}
	options.Check = check.OK()
	if _, err := f.Client.Call(ctx, options); err != nil {
		return fmt.Errorf("shared echo baseline: %w", err)
	}
	if _, err := ConfigDump(ctx, f.Client); err != nil {
		return fmt.Errorf("shared ztunnel config dump: %w", err)
	}
	return nil
}

// ConfigDump fetches the injected ztunnel Envoy config dump through the echo
// instance's admin port.
func ConfigDump(ctx context.Context, instance echo.Instance) (string, error) {
	result, err := instance.Call(ctx, echo.CallOptions{
		Protocol: echo.HTTP, Address: "localhost", Port: 15000, Path: "/config_dump",
		Count: 1, Timeout: 5 * time.Second, Check: check.OK(),
		Retry: retry.Policy{
			Timeout: 5 * time.Second, Delay: 100 * time.Millisecond,
			Backoff: 1.5, MaxDelay: time.Second, Converge: 1,
		},
	})
	if err != nil {
		return "", fmt.Errorf("request ztunnel config dump: %w; attempts: %+v", err, result.Attempts)
	}
	if len(result.Responses) != 1 {
		return "", fmt.Errorf("config dump returned %d responses", len(result.Responses))
	}
	return result.Responses[0].RawContent, nil
}
