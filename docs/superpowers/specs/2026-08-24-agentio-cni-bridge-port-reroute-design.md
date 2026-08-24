# Agentio CNI Bridge Port Reroute Design

## Context

Agentio Ambient CNI currently supports `istio.io/reroute-virtual-interfaces`. For each configured interface, it treats packets entering the Worker Pod network namespace as outbound workload traffic and redirects TCP connections to the ztunnel outbound listener on port `15001`.

This works for the upstream Substrate point-to-point veth topology:

```text
Actor eth0 -> Worker ateom0 -> ztunnel 15001
```

ACK Microsandbox with Dragonball uses a Linux bridge instead:

```text
Actor eth0 -> msb-tapN -> br-msb -> Worker network namespace
```

At the IP prerouting hook, an ordinary input-interface match sees the bridge master rather than the dynamically named TAP port. Matching `br-msb` is too broad because the bridge also carries Worker-to-Actor traffic. The PoC proved that an iptables `physdev` bridge-port match isolates Actor traffic correctly.

## Goals

- Allow an Ambient workload to declare bridge-port name prefixes whose TCP traffic must be treated as outbound workload traffic.
- Support both Agentio CNI in-pod backends: iptables and native nftables.
- Preserve existing virtual-interface behavior and upstream Istio annotation semantics.
- Recreate the rules automatically when CNI enrolls or reconciles a Worker Pod.
- Keep the feature generic and opt-in rather than hard-coding Microsandbox interface names.

## Non-goals

- Automatically detect Substrate, Microsandbox, Dragonball, bridge names, or TAP devices.
- Change Substrate networking or atunnel behavior.
- Add Worker-to-Sandbox management-address exclusions such as `169.254.0.21/32`.
- Implement per-flow identity for multiple concurrent Actors in one Worker network namespace.
- Extend UDP interception; the current ztunnel virtual-interface contract remains TCP-only.

## User-facing API

Agentio CNI will recognize this Pod annotation in Ambient mode:

```yaml
agentio.io/reroute-bridge-port-prefixes: "msb-tap"
```

The value is a comma-separated list of Linux interface-name prefixes. CNI trims surrounding whitespace, removes empty values, and de-duplicates prefixes while preserving their first occurrence.

Values are prefixes rather than backend-specific wildcard expressions. For example, `msb-tap` becomes:

```text
iptables:       --physdev-in msb-tap+
native nftables: meta sdifname "msb-tap*"
```

A prefix must:

- contain only ASCII letters, digits, `.`, `_`, and `-`;
- start with an ASCII letter or digit;
- be no longer than 14 bytes, leaving room for at least one suffix character within Linux's 15-byte interface-name limit.

Invalid prefixes are ignored and logged with the Pod namespace/name. One invalid entry does not disable valid entries from the same annotation. If no valid entry remains, CNI installs no bridge-port rule.

The existing annotation continues to handle ordinary interfaces independently:

```yaml
istio.io/reroute-virtual-interfaces: "ateom0"
```

A Worker may use both annotations when it supports more than one Sandbox network backend.

## Internal model

`config.PodLevelOverrides` gains a `BridgePortPrefixes []string` field. The node agent parses the new annotation into this field before invoking the selected traffic manager.

The parser and validation remain in the node-agent layer because they operate on Kubernetes Pod metadata. The iptables and nftables packages receive only normalized prefixes and translate them to backend-specific rules.

No generated annotation catalog is modified for this Agentio-specific PoC. The annotation key is defined as a local Agentio CNI constant with a comment describing its public contract.

## iptables rules

For every normalized prefix, CNI inserts this pair at the beginning of the in-pod NAT `ISTIO_PRERT` chain, after chain creation and before ordinary inbound handling:

```text
-A ISTIO_PRERT -p tcp \
  -m physdev --physdev-in <prefix>+ \
  -j REDIRECT --to-ports 15001

-A ISTIO_PRERT -p tcp \
  -m physdev --physdev-in <prefix>+ \
  -j RETURN
```

The pair follows the existing virtual-interface redirect/return behavior. It is intentionally evaluated before the general plaintext inbound redirect to `15006`.

The rule does not add `--physdev-is-bridged`: packets addressed to a bridge gateway leave the bridge for the local IP stack and may not satisfy that predicate. The PoC requires only the ingress bridge-port identity.

Opting in requires the host kernel and chosen iptables backend to support the `physdev` match. Failure to restore the requested rule fails Pod traffic enrollment instead of silently running without Actor interception.

## Native nftables rules

For every normalized prefix, CNI inserts the corresponding pair at the beginning of the native nftables Ambient NAT `istio-prerouting` chain:

```text
meta sdifname "<prefix>*" meta l4proto tcp counter redirect to :15001
meta sdifname "<prefix>*" meta l4proto tcp counter return
```

`sdifname` is the slave-device input-interface name exposed to the IP/inet hook, so it represents the bridge port while `iifname` represents the bridge master. This keeps the native nftables transaction in the existing inet NAT table and avoids a second bridge-family table used only for marking.

## Ordering and coexistence

Rule order inside NAT `ISTIO_PRERT` is:

1. Bridge-port prefix redirects.
2. Existing virtual-interface redirects.
3. Existing health-probe exemptions and ordinary inbound capture.

Bridge-port rules are more specific than virtual-interface rules and are placed first to make the intended Actor classification explicit. Existing workloads without the new annotation produce byte-for-byte equivalent rules.

The implementation uses the existing chain deletion and recreation lifecycle, so Pod removal, CNI repair, and node-agent startup reconciliation require no separate cleanup path.

## Error handling and observability

- Empty annotation items are ignored.
- Duplicate valid prefixes produce one rule pair.
- Invalid values are skipped and logged at warning level with the annotation key and Pod identity.
- Backend rule-programming errors retain the existing behavior: enrollment returns an error and the node agent records the failure.
- No fallback to `br-msb` or another bridge master is attempted.

## Testing

Unit tests will cover:

1. Pod annotation parsing, trimming, de-duplication, and invalid-prefix rejection.
2. iptables output containing the `physdev --physdev-in <prefix>+` redirect/return pair before ordinary inbound capture.
3. native nftables output containing the `meta sdifname <prefix>*` redirect/return pair before ordinary inbound capture.
4. Coexistence with `VirtualInterfaces`.
5. No rule changes when the annotation is absent or all values are invalid.

Focused validation commands:

```bash
go test ./cni/pkg/nodeagent ./cni/pkg/iptables ./cni/pkg/nftables
helm lint manifests/charts/agentio
helm template agentio manifests/charts/agentio \
  --set ambient.enabled=true \
  --set sidecarInjector.enabled=true >/dev/null
git diff --check
```

Cluster validation will rebuild only the modified Agentio CNI image, update the existing ACK PoC deployment, recreate the annotated Worker, and verify:

- CNI automatically installs the bridge-port rule without an ephemeral debug-container mutation.
- A Sandbox curl request increments that rule's counter.
- TrafficPolicy allow/deny and SecurityProfile allow/deny results remain unchanged.
- Recreating the Worker restores the rule from the Pod template annotation.

## Rollout and rollback

Rollout is opt-in. Existing Pods are unaffected until their template contains the new annotation and they are enrolled or reconciled by the updated Agentio CNI.

Rollback consists of removing the annotation and recreating or reconciling the Worker Pod. Existing CNI cleanup removes the generated chains and recreates them without bridge-port rules. Downgrading CNI while leaving the annotation present is safe: older versions ignore the unknown annotation, although Actor traffic will no longer be intercepted through this path.
