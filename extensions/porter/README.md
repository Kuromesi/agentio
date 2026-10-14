# Agentio Porter

`agentio-porter` is Agentio's gateway sidecar for the outer HBONE CONNECT stage. It uses the standard Envoy ext_proc protocol on `127.0.0.1:9002`. The configurable HTTP ext_proc provider (EPE or a user-supplied implementation) receives only the inner HTTP traffic and does not need to implement an Agentio CONNECT phase.

Porter follows EPE's `--grpc-port` (9002), `--grpc-health-port` (9003), and `--xds-node-id` flag conventions. The processing listener binds to localhost; health probes use a separate plaintext gRPC listener. The shipped gateway targets port 9002. EPE runs in a separate Pod by default; a custom deployment placing both processors in one Pod must assign distinct ports and update the corresponding gateway endpoints.

## Processing

The gateway captures the source Pod name, namespace and optional Sandbox ID from ztunnel's CONNECT headers into filter state. `ConnectHeaders` parses the observed `x-agentio-sni` header separately. An absent header produces an empty SNI; duplicate, explicitly empty or malformed values fail the request.

For an observed SNI, agentio-porter demands the source Workload through `pkg/xdsclient`. When a Sandbox ID is present, it also demands that Sandbox and checks that its current attester is the source Workload. It evaluates the Sandbox's inline SNI rules first, then the Workload's inline rules. These projections are already compiled and bound by agentiod, including global, namespace and selector policies. The sidecar does not watch Kubernetes, load credentials, or run EPE plugins.

A match returns the compiled action. An unmatched SNI selects passthrough; missing source identity, missing resources, an invalid Sandbox binding or a matched deny rule rejects CONNECT with HTTP 403. Without an observed SNI, the handler returns no TLS metadata and leaves protocol selection to the gateway. Gateway TLS exclusions retain precedence over returned TLS selection metadata.

The generic result is dynamic metadata under `agentio`, currently:

```json
{"agentio":{"tls":{"action":"terminate"}}}
```

The gateway copies the action into `agentio.tls.action` filter state before opening the inner connection. The gRPC exchange ends after one headers response; tunnel bodies, trailers and response headers are not processed. Neither credential injection nor HTTP authorization runs in this stage. CONNECT-UDP continues to bypass the processor.

## Discovery and failure behavior

Workload and Sandbox watches start without wildcard subscriptions. A cache miss waits for the named resource; subsequent updates and removals arrive over Delta ADS. Subscriptions stay active while retained. On deletion, Porter releases the named subscription; current waiters receive not-found, and the next CONNECT subscribes again. Porter uses `pkg/demandcache` to release idle or least recently used subscriptions; xdsclient itself imposes no count limit.

Porter defaults to `--xds-cache-idle-ttl=1m` and `--xds-cache-max-entries=10000`. Workload and Sandbox share these settings and one LRU, keyed by resource type and name. Idle time starts when the last lookup completes; consumer accesses refresh it, but control-plane updates do not. Expiration runs even without new traffic. Eviction releases the subscription and cached view; the next CONNECT waits for a fresh subscription. In-flight lookups are pinned, so the entry count can temporarily exceed the target. Values already returned to a request remain valid and immutable. The limit bounds retained entries, not bytes or process RSS.

Set either value to `0` (`0s` for the duration) to disable that policy; setting both to zero bypasses the wrapper and retains resources until deletion. The wrapper tracks only subscription handles and access metadata, with no second copy of policy values. EPE's wildcard watches are unaffected.

Watch transforms decode and validate resources on the update path. The cache retains only Workload UID, Sandbox UID/attester binding and parsed SNI policies. CONNECT requests read these immutable views without copying or decoding complete Workload/Sandbox payloads. A failed transform rejects the entire response while keeping the previous accepted policies and the ADS stream. Before any successful response, a rejected update does not make the watch ready.

The gateway Pod's projected token authenticates the ADS stream over TLS. The existing gateway authorization applies; no Kubernetes read RBAC is added. Projected tokens and CA roots are reread on new RPCs/handshakes. The cluster ID must match agentiod: source Pod resource names use `<cluster-id>//Pod/<namespace>/<name>`. `--cluster-domain` controls the DNS suffix in the ADS node ID (default `cluster.local`); chart deployments pass `global.clusterDomain`.

The handler has a 4-second processing budget and the gateway allows 5 seconds for ext_proc. The CONNECT filter uses `failure_mode_allow: true`, independently of the HTTP provider's `failureModeAllow`: an absent sidecar, gRPC errors or processing timeouts allow the request to continue without a Porter decision. The gateway then uses its own TLS policy. This supports old and new gateway Pods during rolling upgrades and also means Porter failures can bypass its Workload/Sandbox SNI checks. Explicit Porter denials, including missing source resources and invalid Sandbox bindings, still reject CONNECT. Disconnected ADS state is not used for new SNI decisions. The gRPC health endpoint on port 9003 follows EPE conventions: service `readiness` requires both watches to be synchronized, while `liveness` reports process health. Policy updates affect new CONNECT decisions, not TLS mode changes on established tunnels.

## Deployment

The standalone chart supports both static Envoy gateways and Envoy gateways managed through Gateway API. Porter is deployed by default, independently of EPE:

```yaml
agentiod:
  enableSNITrafficPolicy: true

egressGateway:
  mode: gatewayAPI # or static
  porter:
    cache:
      idleTTL: 1m
      maxEntries: 10000

epe:
  mode: disabled # managed/external also work
```

The chart always deploys the sidecar with Envoy gateways and mounts the gateway's existing token and CA volumes. Agentiod always includes the Porter call in every Envoy gateway's precompiled configuration; no control-plane enablement switch or per-instance metadata marker is required. Older Pods without the sidecar continue after the failed local call. This assumes their Envoy build supports the generated filter configuration; `failure_mode_allow` does not handle configuration rejection. `agentiod.enableSNITrafficPolicy` controls consumption of TLS decisions; it does not select the CONNECT endpoint. The agentgateway-native data plane is not wired to this Envoy ext_proc sidecar.

For a manually managed Envoy gateway, deploy agentio-porter in its Pod, mount those same credentials, set `POD_NAME`, `POD_NAMESPACE`, `POD_UID` and `POD_IP`, and pass `--xds-address` and `--cluster-id`. No additional agentiod setting is needed to enable the CONNECT call. The local ext_proc port is fixed at 9002 in gateway configuration; do not expose it through a Service.

## Build and test

From the repository root:

```sh
make build.porter
go test ./extensions/porter/...
docker build -f extensions/porter/docker/Dockerfile -t agentio-porter:dev .
```

Set `egressGateway.porter.image.repository` and `.tag` or `.digest` to use a custom image. The image and release workflows build `agentio-porter` and pin its digest in release charts.

Product E2E enables Porter in both sidecar and ambient profiles. Supply an immutable `AGENTIO_E2E_PORTER_IMAGE` alongside the other [E2E image inputs](../../test/e2e/README.md). The gateway suite covers no-SNI HTTP and TLS termination with a custom application ext_proc; the securitypolicy suite covers selection, wildcard matching, hot updates, deletion and recreation.
