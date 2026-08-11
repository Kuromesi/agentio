# Agentio and Istio

Agentio is built from Istio's control-plane and data-plane foundations, but it is not configured as a general-purpose Istio service mesh by default. It narrows those foundations around traffic governance for agents, sandboxes, and other untrusted workloads.

Agentio reuses Pilot and xDS, Kubernetes workload and service discovery, admission injection infrastructure, Gateway API integration, and selected Istio data-plane components. It changes the APIs that form the supported configuration surface and the proxy that runs beside an enrolled workload.

> An Agentio installation should not be treated as a drop-in Istio installation. A resource or annotation being part of the inherited Istio codebase does not mean it is watched or effective in the default Agentio deployment.

## Default behavior at a glance

| Area | Istio default model | Agentio default model |
| --- | --- | --- |
| Control plane | `istiod` watches Istio networking, security, telemetry, and extension APIs. | `agentiod` reuses Pilot/xDS but limits custom-resource discovery to Kruise and Gateway API resources. |
| Sidecar mode | Injects an Envoy proxy into each enrolled Pod. | Reuses Istio injection selectors but injects the ztunnel image into each enrolled Pod. |
| Ambient mode | Uses node-level ztunnel for Layer 4 and optional waypoint proxies for Layer 7. | Uses node-level CNI and ztunnel, extended with Agentio workload and egress-policy configuration. |
| Workload policy | Uses Istio APIs such as `AuthorizationPolicy`, `PeerAuthentication`, and `RequestAuthentication`. | Uses `TrafficPolicy` and `GlobalTrafficPolicy` from `agents.kruise.io/v1alpha1`. |
| Egress routing | Commonly uses `ServiceEntry`, `VirtualService`, `DestinationRule`, and an optional egress gateway. | Uses ordered `egressPolicies` from Agentio configuration to select `PASSTHROUGH`, `DENY`, or `GATEWAY`. |
| Mesh-internal traffic | Discovers and configures service-to-service traffic as part of the mesh. | The chart defaults `MESH_INTERNAL_TRAFFIC_POLICY` to `PASSTHROUGH`, keeping the primary focus on controlled egress. |
| Envoy | Envoy is the per-Pod sidecar and is also used for gateways. | Per-Pod and node-level capture use ztunnel; the Agentio egress gateway still uses Envoy. |

These are comparisons of the standard installations, not a complete feature-by-feature compatibility matrix.

## Resource discovery is intentionally narrow

The standard Agentio chart configures `agentiod` with:

```yaml
- name: PILOT_IGNORE_RESOURCES
  value: "*."
- name: PILOT_INCLUDE_RESOURCES
  value: "*.kruise.io,*.gateway.networking.k8s.io"
```

The include list restores Kruise and Kubernetes Gateway API custom resources after the broad exclusion. Core Kubernetes resources needed for workload and service discovery are still watched.

As a result, an ordinary Agentio installation does not watch or distribute Istio networking, security, or telemetry custom resources such as:

- `VirtualService`, `DestinationRule`, `ServiceEntry`, and the Istio `Gateway` API;
- `AuthorizationPolicy`, `PeerAuthentication`, and `RequestAuthentication`;
- `Telemetry`, `EnvoyFilter`, `WasmPlugin`, and `ProxyConfig`.

This is a default support boundary, not a claim that the inherited Pilot code has been physically removed. Changing the resource filters is an advanced deployment change and does not by itself make undocumented Istio APIs part of Agentio's supported configuration surface.

## Sidecar mode uses ztunnel

Istio sidecar mode injects Envoy. Agentio keeps Istio's familiar `istio-injection` namespace label and `sidecar.istio.io/inject` Pod annotation so it can reuse the admission-injection machinery, but its default injection template uses the ztunnel image and applies this label:

```yaml
networking.agents.kruise.io/proxy-type: ztunnel
```

The injected container retains the conventional name `istio-proxy`. Inspect the Pod image and the `proxy-type` label rather than using the container name to decide whether the Pod runs Envoy or ztunnel:

```console
$ kubectl get pod <pod> --namespace <namespace> \
    --output jsonpath='{.spec.containers[?(@.name=="istio-proxy")].image}{"\n"}'
$ kubectl get pod <pod> --namespace <namespace> \
    --output jsonpath='{.metadata.labels.networking\.agents\.kruise\.io/proxy-type}{"\n"}'
```

Agentio's per-Pod ztunnel focuses on traffic capture, workload identity metadata, ordered egress decisions, and forwarding to the selected egress gateway. It does not receive the normal Envoy listener, route, and cluster configuration implied by standard Istio sidecar usage.

## Ambient mode separates capture from forwarding

Agentio ambient mode does not add a proxy container to application Pods:

- the node-level CNI component programs traffic-capture rules;
- the node-level ztunnel performs the actual traffic forwarding;
- `agentiod` distributes Agentio workload metadata, egress policies, and traffic policies to the data plane.

This separation is similar to Istio ambient's node-level architecture, while the configuration and policy surface remains Agentio-specific.

## The egress gateway still uses Envoy

Agentio has not removed Envoy from the data plane. When an `egressPolicies` rule selects `GATEWAY`, ztunnel forwards the connection to an Envoy-based Agentio egress gateway. The gateway can call EPE (the Egress Policy Enforcer) through Envoy `ext_proc` for policy enforcement and can apply Agentio-specific TLS termination, timeout, retry, and rate-limit settings.

This creates two distinct proxy roles:

- **ztunnel** captures and forwards traffic for enrolled workloads, either per Pod or per node;
- **Envoy egress gateway** performs centralized processing for traffic selected by a `GATEWAY` rule.

## Configuration mapping

| Intent | Agentio configuration |
| --- | --- |
| Enroll a regular Pod with per-Pod capture | Sidecar injection with the ztunnel template |
| Enroll Pods without adding proxy containers | Ambient namespace enrollment, CNI, and node-level ztunnel |
| Select direct, denied, or gateway egress | `egressPolicies` in `agentio-config` or `agentio-config-primary` |
| Apply workload traffic policy | `TrafficPolicy` or `GlobalTrafficPolicy` |
| Configure gateway TLS, external processing, timeouts, or rate limits | `egressGateways` in Agentio configuration |

Agentio preserves some Istio-compatible labels, annotations, and component names where they help reuse the upstream infrastructure. Treat those as integration details; use the Agentio documentation and APIs as the source of truth for supported behavior.

## See also

- [Getting started](../getting-started.md)
- [Sidecar mode](../getting-started/sidecar-mode.md)
- [Ambient mode](../getting-started/ambient-mode.md)
