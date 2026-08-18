# Gateway SNI policy Wasm

This Rust network Wasm filter reads the SNI already extracted by Envoy's TLS
inspector from `connection.requested_server_name` and the workload's resolved
policy snapshot from `filter_state/agentio.bound_policies`. It selects the
`SniTrafficPolicy` group by TypeURL, decodes only that group's opaque protobuf
resources, applies the first matching rule, and writes the selected cluster to
`envoy.tcp_proxy.cluster`. Missing, pending, and malformed SNI policy snapshots
fail closed.

Agentiod supplies the physical route targets through the Wasm plugin
configuration as `termination_cluster` and `passthrough_cluster`. The module
contains no built-in Envoy cluster names.

The type-neutral FilterState contract is defined in
`api/v1/policy_snapshot.proto`. Its policy resources remain serialized
protobuf bytes grouped by TypeURL, so the native policy discovery component
does not need to understand or be rebuilt for each new BindablePolicy type.
The corresponding native data-plane contract must keep the field numbers,
enum values, and package names wire compatible.

The complete data plane uses matching `codex/gateway-sni-traffic-policy`
branches based on `sandbox/release-0.1` in these repositories:

- `envoy`/`proxy`: native policy discovery and the type-neutral
  `agentio.bound_policies` FilterState object.
- `proxy`: trusted WDS workload name/namespace propagation and final Envoy link target.
- `agentio`: this Rust Wasm module, bootstrap/xDS generation, policy
  translation, CRD, and Helm wiring.

Build the module with Rust 1.85:

```bash
make BUILD_WITH_CONTAINER=0 build.sni-policy-wasm
```

The standalone artifact is
`extensions/wasm/snitrafficpolicy/target/wasm32-wasip1/release/agentio_sni_policy_wasm.wasm`.
The `agentio-sni-policy-wasm` image plan packages it as `/plugin.wasm` in a
scratch OCI image. Agentiod reads the image from `SNI_TRAFFIC_POLICY_WASM_IMAGE`
and publishes the module through an Agentio-owned ECDS resource. The module is
not embedded in `proxyv2`.

The repository image target is:

```bash
make docker.agentio-sni-policy-wasm HUB=<registry/repository> TAG=<tag>
```
