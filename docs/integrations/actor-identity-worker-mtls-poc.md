# Actor identity over Worker mTLS PoC

This PoC adds Actor-level policy metadata to Agentio's single-Actor Worker
model without issuing a separate mTLS certificate for every Actor. The Worker
Pod certificate remains the transport identity. `agentiod` derives a trusted
`ActorContext` from the current Worker workload and sends it only to that
Worker's ztunnel over WCDS.

The PoC is intended for a Worker Pod that runs exactly one Actor at a time. It
does not make multiple concurrent Actors in one network namespace
distinguishable.

## Identity and trust model

The request path has two identity layers:

1. The ztunnel-to-gateway HBONE connection uses the Worker Pod certificate for
   mTLS. The gateway continues to authenticate the Worker service account.
2. The HBONE CONNECT request carries the current Actor UID, generation, labels,
   and optional Actor token. The gateway copies these values to filter state so
   EPE can evaluate Actor labels and expose the Actor UID and generation.

The Actor metadata is trusted because it is produced by `agentiod`, delivered
to the Worker ztunnel over xDS, and transported inside the authenticated Worker
HBONE connection. The PoC does not give the Actor a separately verifiable
SPIFFE identity. A signed Actor token can provide an additional independent
proof when the Actor runtime supplies one.

## Worker label contract

The Actor controller binds an Actor to its Worker by setting all of the
following Pod labels:

```yaml
metadata:
  labels:
    networking.agents.kruise.io/proxy-type: ztunnel
    networking.agents.kruise.io/actor-uid: actor-7b93d
    networking.agents.kruise.io/actor-name: crawler
    networking.agents.kruise.io/actor-atespace: tenant-a
    networking.agents.kruise.io/actor-generation: "7"
    actor.networking.agents.kruise.io/role: reader
    actor.networking.agents.kruise.io/team: search
```

`actor-uid`, `actor-name`, `actor-atespace`, and a non-zero unsigned
`actor-generation` are mandatory. If any field is missing or invalid,
`agentiod` omits `ActorContext` and ztunnel sends no Actor identity headers.

Labels prefixed with `actor.networking.agents.kruise.io/` become Actor labels
without that prefix. `agentiod` also supplies these canonical labels:

```text
agentio.io/actor-uid
agentio.io/actor-name
agentio.io/atespace
agentio.io/actor-generation
```

Use a monotonically increasing generation for every Actor assignment, even if
the same Actor UID is assigned again. Changing either the Actor UID or the
generation makes ztunnel immediately close existing tracked connections. New
connections use only the new ActorContext.

## Actor token mount

An Actor token is optional for metadata-based policy matching, but recommended
when the gateway needs an independently signed Actor assertion. The Actor
runtime or Worker supervisor, not `agentiod`, writes the token into a volume
mounted in the ztunnel container.

ztunnel watches `SANDBOX_TOKEN_PATH`, whose default is:

```text
/var/opt/sandbox/agent-token/
```

The filename must be the exact Actor UID plus `.token`:

```text
/var/opt/sandbox/agent-token/actor-7b93d.token
```

For example, an externally managed `traffic-proxy` injection template can
mount a shared volume and set the path explicitly:

```yaml
env:
- name: SANDBOX_TOKEN_PATH
  value: /var/run/agentio/actor-tokens
volumeMounts:
- name: actor-token
  mountPath: /var/run/agentio/actor-tokens
  readOnly: true
```

The supervisor must publish the token atomically and remove the previous
Actor's file during reassignment. ztunnel selects only
`<current-actor-uid>.token`; unrelated files are ignored for request identity.

## Wire contract

For an Actor-bound Worker, ztunnel adds these headers to the outbound HBONE
CONNECT request:

| Header | Value |
| --- | --- |
| `x-agentio-sandbox-id` | Actor UID |
| `x-agentio-sandbox-generation` | Decimal Actor generation |
| `x-agentio-sandbox-labels` | Base64 of sorted `key=value` Actor labels |
| `x-agentio-sandbox-token` | Base64 of the exact Actor token file, when present |

The gateway maps them to `sandbox.id`, `sandbox.generation`, `sandbox.labels`,
and `sandbox.token` filter state. EPE keeps `Peer.Pod` as the authenticated
Worker Pod and separately exposes `Peer.ActorUID` and
`Peer.ActorGeneration`. `Peer.Labels` contains Actor labels when ActorContext
is present, so existing `SecurityProfile` selectors can be used for Actor-level
egress policy in this PoC.

Workers without ActorContext retain the existing Sandbox behavior: ztunnel
sends the Worker's workload labels and leaves the Actor UID and generation
empty. This keeps existing non-Actor SecurityProfile selectors compatible.

For example:

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: actor-reader
  namespace: worker-namespace
spec:
  selector:
    matchLabels:
      role: reader
      agentio.io/atespace: tenant-a
  rules:
  - name: block-example
    match:
    - domains:
      - www.example.com
      methods:
      - POST
    actions:
      block:
        statusCode: 403
        body: actor request blocked
```

The namespaced `SecurityProfile` is still looked up by the Worker Pod
namespace; `actor-atespace` is an Actor label, not a Kubernetes namespace
override. Use `GlobalSecurityProfile` when Actors from multiple Worker
namespaces should share one selector.

## Reassignment sequence

Use this order when changing the Actor running in a Worker:

1. Stop new traffic from the old Actor and terminate the old Actor process.
2. Atomically publish the new Actor token and remove the old token.
3. Update the Worker labels in one Kubernetes patch, including an incremented
   generation.
4. Wait for `agentiod` to send the new WCDS resource. ztunnel drains existing
   connections when it observes the binding change.
5. Start or release traffic from the new Actor.

Example patch:

```console
$ kubectl label pod "$WORKER_POD" -n "$WORKER_NAMESPACE" --overwrite \
    networking.agents.kruise.io/actor-uid=actor-7b93d \
    networking.agents.kruise.io/actor-name=crawler \
    networking.agents.kruise.io/actor-atespace=tenant-a \
    networking.agents.kruise.io/actor-generation=7 \
    actor.networking.agents.kruise.io/role=reader
```

Remove the binding when the Worker becomes idle:

```console
$ kubectl label pod "$WORKER_POD" -n "$WORKER_NAMESPACE" \
    networking.agents.kruise.io/actor-uid- \
    networking.agents.kruise.io/actor-name- \
    networking.agents.kruise.io/actor-atespace- \
    networking.agents.kruise.io/actor-generation- \
    actor.networking.agents.kruise.io/role-
```

## Validation

The focused Agentio checks are:

```console
$ go test ./pilot/pkg/serviceregistry/kube/controller/agentio/... \
    ./pilot/pkg/serviceregistry/kube/controller/ambient \
    ./pilot/pkg/xds ./pilot/pkg/xds/filters \
    ./extensions/epe/pkg/extproc/attributes -count=1
```

The focused ztunnel checks are:

```console
$ cargo test --lib actor_context_is_stored_and_replaced_with_workload_config \
    --no-default-features -F tls-boring
$ cargo test --lib actor_context_headers_select_matching_token \
    --no-default-features -F tls-boring
$ cargo test --lib test_policy_watcher_closes_connections_on_actor_generation_change \
    --no-default-features -F tls-boring
```

## PoC limitations

- Multiple simultaneous Actors in one Worker network namespace need an
  additional per-flow discriminator and are out of scope.
- `actor-atespace` does not change the Worker's Kubernetes namespace or mTLS
  principal.
- Actor labels are ActorContext metadata carried by the trusted Worker
  ztunnel; they are not independently signed unless the optional Actor token is
  validated by policy.
- This change defines the Agentio and ztunnel contract. The Actor runtime still
  needs to manage Worker labels and token lifecycle in the sequence above.
