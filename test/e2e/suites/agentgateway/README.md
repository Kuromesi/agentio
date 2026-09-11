# Agentgateway e2e

This suite installs the production Agentio chart, its real gatewaydeployer, ztunnel, the pinned echo workload, and the shared ext-proc fixture. It provisions `agentio-agentgateway` Gateways backed by native static ConfigMaps.

The suite reuses `harness.RunGatewayTraffic`, `RunGatewayExtProc`, and `RunGatewayMatchPorts` with the Envoy gateway suite. HTTP and gRPC traversal proofs use a native gateway header mutation instead of Envoy-specific response headers and access-log fields. Traffic crosses the injected ztunnel and a native `hboneGateway` mTLS CONNECT tunnel. The chart enables `egressGateway.agentgateway.ca.enabled`: gateway Pods request and renew their workload certificates directly from Agentiod using projected ServiceAccount tokens. HTTPS is passed through without interception.

`TestAgentgatewayDeploymentLifecycle` covers class acceptance, missing config, initial provisioning, config rollout, invalid YAML, rejection by the native binary while the old replica continues serving, recovery, Service recreation, Gateway deletion/child garbage collection, and Gateway recreation. Rollout checks require the expected config hash and fully updated Deployment replicas; a stale `Programmed=True` does not count as completion.

## Run

Use an isolated Kubernetes cluster with Gateway API v1.4.1 standard CRDs already installed. As with the other suites, provide immutable images for Agentiod, EPE, ext-proc, ztunnel, proxy-init, and CNI using the component flags or an `-agentio.config` file. Set `gateway-image` to an agentgateway digest (verified with v1.5.0), not the Envoy image. From `test/e2e`:

```bash
AGENTIO_E2E=1 go test ./suites/agentgateway -v -timeout=25m \
  -e2e.cluster.mode=existing \
  -e2e.cluster.kubeconfig="$KUBECONFIG" \
  -e2e.artifacts.dir="$ARTIFACTS" \
  -e2e.lifecycle.retain=on-failure \
  -agentio.config="$AGENTIO_CONFIG" \
  -agentio.gateway-dataplane=agentgateway \
  -agentio.profile=sidecar
```

A cross-compiled `go test -c` binary accepts the same flags, with `-test.v` and `-test.timeout` instead of `-v` and `-timeout`. To run remotely, copy the binary and production chart to the test host and supply its kubeconfig and chart path.

## Scope

The suite uses the production native CA bootstrap; it does not read CA private keys or create gateway certificate Secrets. The native HBONE gateway routes using the CONNECT destination IP and port, with explicit internal binds for the echo fixture ports; outer CONNECT Host overrides and synthetic destinations are outside this suite's scope. Long-running certificate renewal and rejection/recovery are exercised separately by `TestAgentgatewayNativeCACertificateRotation` in `pkg/security/ca` (see the [deployment guide](../../../../docs/tasks/deploy-agentgateway.md#end-to-end-coverage)). The suite does not test per-Sandbox identity authorization, dynamic SNI policy, SecurityProfile/EPE policy translation, TLS interception, or Gateway API HTTPRoute translation. Native ext-proc header mutations do not claim compatibility with the full EPE suite. The suite targets the sidecar profile; ambient needs a separate run.
