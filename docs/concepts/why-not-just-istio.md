# Why not just Istio?

Agentio is built on Istio, and Istio can control egress traffic. The difference is the subject and level of abstraction around which that control is organized. Istio's ambient waypoint model normally attaches Layer 7 processing to a destination resource, and its traffic management and authorization APIs protect and govern individual services. Agentio starts with the potentially untrusted client, establishes a common path for its outbound traffic, and defines what that client is allowed to reach.

## Egress routing starts from a different subject

### Istio ambient: the destination selects a waypoint

In Istio ambient mode, a waypoint acts as a gateway to a destination resource. To send traffic for an external API through a waypoint, a common pattern is to represent that API with a `ServiceEntry`, then label the `ServiceEntry` to use a service waypoint:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: external-api-waypoint
  namespace: egress-control
  labels:
    istio.io/waypoint-for: service
spec:
  gatewayClassName: istio-waypoint
  listeners:
  - name: mesh
    port: 15008
    protocol: HBONE
---
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: api-example-com
  namespace: egress-control
  labels:
    istio.io/use-waypoint: external-api-waypoint
spec:
  hosts:
  - api.example.com
  location: MESH_EXTERNAL
  ports:
  - number: 80
    name: http
    protocol: HTTP
  resolution: DNS
```

The routing choice belongs to `api-example-com`: requests addressed to that external service use `external-api-waypoint`. A different external destination does not use the waypoint merely because the request came from the same client; that destination must also be represented and enrolled when it needs the same processing path.

This destination-oriented behavior is intentional. Istio describes a waypoint as a gateway to a namespace, service, or workload, and the `istio.io/use-waypoint` label selects the waypoint used by that resource. See the Istio documentation for [waypoint proxies](https://istio.io/latest/docs/ambient/usage/waypoint/) and [`ServiceEntry`](https://istio.io/latest/docs/reference/config/networking/service-entry/).

### Agentio: the source sandbox selects an egress gateway

Sandbox traffic starts from a different question: which gateway must this untrusted client use, regardless of the destination it chooses at runtime?

Agentio evaluates ordered `egressPolicies`. The current source selector is namespace-scoped, while destination hosts, CIDRs, and ports are optional. Omitting every destination matcher makes the first rule below apply to all outbound traffic from `sandbox-a`:

```yaml
egressPolicies:
- namespaces:
  - sandbox-a
  policy: GATEWAY
  gateway:
    service: agentio-egress.agentio-system.svc.cluster.local
- policy: PASSTHROUGH
```

The first rule sends every destination selected by clients in `sandbox-a` through `agentio-egress`. The second rule leaves traffic from other namespaces on the passthrough path. This routing policy does not require a `ServiceEntry` for every destination.

The current API selects a source namespace rather than an individual Pod, ServiceAccount, or workload label. Deploy a sandbox, or a group of sandboxes with the same egress boundary, in a dedicated namespace when it needs an independent gateway selection policy.

Routing all destinations through a gateway does not mean allowing all destinations. It ensures that even previously unknown destinations reach the gateway, where EPE (the Egress Policy Enforcer) and other gateway policy can inspect the request and decide whether it should continue.

### Why this matters for sandboxes

A conventional service usually has a small, reviewable set of dependencies. An agent or sandbox may choose destinations dynamically, load tools at runtime, execute generated code, or become compromised. Requiring every future destination to be known before it can enter the controlled path leaves the routing boundary tied to an incomplete service inventory.

Agentio instead ties the egress path to the source sandbox's trust boundary. New and unexpected destinations still traverse the selected gateway. The destination remains available as a policy input, but it is no longer the resource that decides whether the client reaches the enforcement point.

## Traffic management starts at a different level of abstraction

### Istio: fine-grained, service-specific traffic management

Istio is designed to support detailed traffic management across services. When that level of control is needed, a `VirtualService` can match request properties and select a route, while a `DestinationRule` can define service subsets and policies that apply after routing. For example, the following configuration sends requests with a particular header to version `v2` of a service and all other requests to `v1`:

```yaml
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: reviews
  namespace: default
spec:
  hosts:
  - reviews.default.svc.cluster.local
  http:
  - match:
    - headers:
        x-api-version:
          exact: v2
    route:
    - destination:
        host: reviews.default.svc.cluster.local
        subset: v2
  - route:
    - destination:
        host: reviews.default.svc.cluster.local
        subset: v1
---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: reviews
  namespace: default
spec:
  host: reviews.default.svc.cluster.local
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
```

This model is valuable for canary releases, traffic splitting, request-based routing, retries, timeouts, circuit breaking, and service-specific load balancing. These resources are optional in Istio, but using those capabilities requires operators to model the relevant services, versions, and routing rules. See Istio's [traffic management concepts](https://istio.io/latest/docs/concepts/traffic-management/) for the complete model.

### Agentio: a common enforcement path for sandbox traffic

Most sandbox deployments do not need to choose between application versions or maintain different routing behavior for every destination. Their primary requirement is usually simpler: all traffic from an untrusted client must pass through a controlled gateway, where a common policy can decide whether the request is allowed.

The namespace-scoped `egressPolicies` example above establishes that invariant without requiring a `VirtualService` or `DestinationRule` for each service. The destination and request context can remain runtime inputs to EPE policy enforcement instead of becoming a growing graph of service-specific routing resources.

This is a deliberately coarser routing model, not an absence of control. Agentio separates the stable traffic invariant — which clients must traverse which enforcement point — from the dynamic security decision — which requests may continue. Fine-grained service traffic management can still be introduced where it is genuinely needed, but it is not the baseline configuration required to secure a sandbox.

## Authorization protects a different subject

### Istio: the server defines who may access it

Istio's `AuthorizationPolicy` is attached to the workload or resource being protected. Its rules can match client identity, namespace, IP address, request method, path, and other attributes, but the policy is evaluated from the destination's point of view: which callers and operations should this server accept?

For example, assuming the caller's workload identity is authenticated, this policy protects the `reviews` workload and allows only the `frontend` ServiceAccount to send `GET` requests:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: reviews-access
  namespace: default
spec:
  selector:
    matchLabels:
      app: reviews
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/frontend/sa/frontend
    to:
    - operation:
        methods:
        - GET
```

The owner of `reviews` defines who may call it. Other services define their own policies. In ambient mode, a policy can instead use `targetRefs` to attach to a `Service` or `ServiceEntry` through a waypoint, but the protected destination remains the policy target. See Istio's [`AuthorizationPolicy` reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/).

### Agentio: the platform defines what the client may access

For an untrusted sandbox, the more important boundary is often the inverse: what destinations is this client allowed to reach, even when those destinations do not belong to the same platform or cannot enforce an Istio policy?

Agentio separates client-side authorization into two enforcement layers. `TrafficPolicy` provides Layer 4 controls enforced by ztunnel, while `SecurityProfile` provides Layer 7 controls enforced at the egress gateway through EPE.

The `TrafficPolicy` selector identifies the client workload, and its `egress` rules describe the network destinations and ports that workload may reach. The following policy allows the selected sandbox to use cluster DNS and access `api.example.com`; unmatched outbound traffic is rejected by ztunnel:

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: sandbox-egress
  namespace: sandbox-a
spec:
  selector:
    matchLabels:
      app: sandbox
  egress:
    rules:
    - action: allow
      to:
      - service:
          name: kube-dns
          namespace: kube-system
    - action: allow
      to:
      - fqdn: api.example.com
```

This Layer 4 boundary applies before the request reaches the application-aware gateway. It can restrict destination services, CIDRs, FQDNs, ports, and protocols, but it does not interpret HTTP paths, methods, headers, or query parameters.

When traffic is routed through an egress gateway with EPE enabled, the gateway sends request attributes to the extension for Layer 7 policy enforcement. A `SecurityProfile` selects the same sandbox by label and defines application-level rules. The following example blocks access to the `/admin` path on `api.example.com` while allowing other requests to continue:

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: sandbox-l7-egress
  namespace: sandbox-a
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: block-admin-api
    match:
    - domains:
      - api.example.com
      paths:
      - type: Prefix
        value: /admin
      methods:
      - GET
      - POST
      - PUT
      - DELETE
    actions:
      block:
        statusCode: 403
        body: '{"error":"admin API access is blocked"}'
```

`SecurityProfile` rules use default-continue semantics: this terminal `block` action rejects matching requests at the gateway, while requests that do not match a blocking rule continue to the upstream destination. Domain, path, method, port, header, and query-parameter matching can be combined when a sandbox needs more precise controls. The complete API is defined by the repository's [`SecurityProfile` CRD](../../manifests/charts/agentio/files/securityprofile-crd.yaml).

Together, these layers change policy ownership. A sandbox platform operator can define both the network destinations and the application operations available to each client without coordinating with every destination owner or assuming that every destination participates in the mesh. Server-side authorization remains valuable as defense in depth, but it cannot replace a client-side boundary when the client itself is the untrusted component.

## See also

- [Agentio and Istio](agentio-and-istio.md)
- [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [Agentio configuration](../reference/agentio-configuration.md)
