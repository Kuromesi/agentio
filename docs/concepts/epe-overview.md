# Egress Policy Enforcer overview

The Egress Policy Enforcer (EPE) applies content-aware HTTP policy to Agentio workload traffic that is routed through an Agentio egress gateway. It is the layer to use when a decision depends on the HTTP request, such as the target host and path, request headers, an MCP tool call, or a credential transformation.

EPE does not capture workload traffic and it does not select its own traffic path. Agentio's sidecar or ambient data plane captures enrolled workload traffic; the egress route decides whether that traffic reaches an egress gateway. On a gateway-routed HTTP request, the gateway's Envoy external-processing (`ext_proc`) filter calls the `agentio-epe` Service. Requests on the direct passthrough path do not call EPE.

```text
enrolled workload
  -> Agentio traffic capture
  -> egress gateway selected by egress routing
  -> Envoy ext_proc
  -> agentio-epe
  -> external service, or an EPE response
```

## What EPE complements

`TrafficPolicy` and `GlobalTrafficPolicy` govern L3/L4 egress authorization and routing eligibility for selected workloads. They decide whether a workload may reach a destination and, together with the egress route, whether the gateway path is used.

`SecurityProfile` and `GlobalSecurityProfile` are EPE's L7 policy resources. They select workloads, match HTTP requests, and can block a request, bypass remaining EPE work, transform credentials, enforce an MCP tool policy, or emit an audit event. A SecurityProfile cannot make an otherwise direct passthrough request visit EPE, and an EPE allow-like result cannot grant a destination that `TrafficPolicy` has rejected.

## Primary resources and actions

- A namespaced `SecurityProfile` applies only to Pods in its namespace that match its selector.
- A cluster-scoped `GlobalSecurityProfile` can select Pods in every namespace. Use it for centrally owned, cluster-wide policy; set priorities deliberately because it shares one evaluation order with namespaced profiles.
- A rule contains one or more HTTP match clauses. The `domains` field is required; paths, methods, ports, schemes, headers, and query parameters further restrict a match.
- `block` returns an HTTP response without forwarding upstream. `bypass` forwards the request but skips every remaining EPE action and rule. `tokenTransformation` is non-terminal and can rewrite a request credential. `mcpToolPolicy` can inspect a buffered MCP request and deny it. `audit` sends an asynchronous event and never changes the request decision.

## Operational boundaries

EPE is a network hop on each gateway-routed request. Its work adds processing latency, and policies that need a request body require Envoy to buffer the complete body before the decision. Size EPE independently of the gateway and keep the chart's `agentio-epe` Deployment healthy; its headless Service exposes ext-proc on port `9002`, health on `9003`, and metrics on `9090` by default.

EPE needs the caller identity and labels that the gateway sends as ext_proc attributes. If that identity is absent, EPE cannot select a profile and the request passes through unmodified. This is an availability-friendly but security-significant failure mode: validate enforcement with real gateway-routed traffic and monitor the EPE logs and metrics.

Profile inputs, request headers, pod labels, and audit payloads can contain sensitive information. Give EPE's cluster-wide read permissions and audit webhook destinations the same review as other security control-plane components. EPE's expression scope intentionally excludes request bodies and sandbox identity tokens, but an audit template can disclose the request and profile data that it is given; send audit events only to trusted endpoints.

## See also

- [EPE policy evaluation](epe-policy-evaluation.md)
- [Get started with EPE](../getting-started/epe.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md)
