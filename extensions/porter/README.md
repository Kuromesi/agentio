# Agentio Porter

Porter resolves the source Workload and its SNI policies for the gateway's outer HBONE CONNECT request. It implements standard Envoy ext_proc on `127.0.0.1:9002`; application HTTP processing remains with EPE or the configured HTTP ext_proc provider.

The gateway captures Workload name, namespace and optional Sandbox ID from the trusted ztunnel CONNECT headers into filter state. Porter demands the Workload through Delta ADS, checks its identity and, when present, checks the Sandbox's attester binding. When either workload header is missing, Porter resolves the physical HBONE peer IP through the existing default-network Workload alias (`/<IP>`) and requires its namespace, ServiceAccount and trust domain to match the authenticated client certificate URI SAN. Any supplied partial identity must also match. Unknown or ambiguous IPs, host-network workloads and identity mismatches reject CONNECT; complete but invalid headers do not trigger fallback. This path requires direct sidecar connections with the source Pod IP preserved; it does not resolve through SNAT or intermediate proxies. Porter does not evaluate an SNI supplied in request headers. The gateway exposes certificate principals as `agentio.peer.principal` and `agentio.local.principal`; Porter reads only `agentio.peer.principal`. Custom CEL expressions for the new gateway must use these keys. Legacy waypoint configurations retain `io.istio.peer_principal` and `io.istio.local_principal`.

Porter combines compiled Sandbox rules followed by Workload rules and returns canonical `SniTrafficPolicy` JSON in dynamic metadata under `agentio.sni.policy`. After ext_proc, the gateway copies the resolved workload name and namespace into hashable, transitively shared filter state for EPE and connection isolation, even when SNI policy is disabled. The gateway copies `%DYNAMIC_METADATA(agentio:sni:policy)%` into hashable `agentio.sni.policy` filter state before opening the internal connection. The Rust listener module evaluates Envoy TLS inspector's actual SNI and writes `agentio.tls.action` to select termination, passthrough or denial. Gateway exclusions take precedence. A valid empty policy selects passthrough; missing or malformed policy denies detected TLS.

Workload and Sandbox subscriptions start without wildcard requests. The demand cache keeps subscriptions while retained and receives policy updates and removals. Disconnected ADS state is not used for new requests. The default processing budget is 4 seconds; Envoy allows 5 seconds and uses `failure_mode_allow: false`. Policy changes apply to new CONNECT requests. CONNECT-UDP also uses Porter once at tunnel establishment for Workload resolution and Sandbox binding checks, including the same IP fallback. Envoy presents it as `GET` with `Upgrade: connect-udp`. Porter returns only workload metadata for UDP; the gateway skips SNI policy transfer and forwards datagrams directly without inspection.

The projected gateway Pod token authenticates ADS. Agentiod verifies Pod identity and Gateway membership before accepting `agentio-porter~<Pod IP>~<Pod name>.<namespace>~<DNS domain>`; Envoy and Porter share the `ClientAgentioEgress` class, which allows Envoy xDS resources plus Workload and Sandbox. Porter itself subscribes only to Workload and Sandbox. No Kubernetes read RBAC is needed. `--cluster-id` must match Agentiod because Workload resource names use `<cluster-id>//Pod/<namespace>/<name>`.

Both static and Gateway API chart deployments include Porter with the gateway's token and CA volumes. Configure `egressGateway.porter.image`, `.resources` and `.cache` (`idleTTL: 1m`, `maxEntries: 10000`). A manual deployment sets `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, `POD_IP`, `--xds-address` and `--cluster-id`. The health listener on port 9003 serves gRPC `readiness` after both discovery watches synchronize, and `liveness` for process health. Do not expose the processing port through a Service.

Porter uses the same structured logging configuration as Agentiod: `AGENTIO_LOG_LEVEL` defaults to `info` (`debug`, `info`, `warn`, `error`, `none`), and `AGENTIO_LOG_FORMAT` defaults to `text` (`text` or `json`). Set these on the Porter container. Info logs report startup settings, listener addresses, readiness transitions and shutdown; xDS disconnections and rejected responses remain warnings. Debug logs add CONNECT processing duration, gRPC result, identity resolution (including peer-IP fallback), rejection reasons and SNI rule counts. They do not dump headers, tokens, Sandbox IDs or policy contents. Porter prepares SNI policy metadata; the Rust module makes the final TLS decision, so use gateway access logs for that outcome.

During migration, authenticated `waypoint~` clients retain their original forwarding and TLS configuration, peer discovery and policy runtime. Only `agentio-egress~` clients receive Porter and dynamic modules. The control plane stores both graphs separately; the gateway agent has no legacy bootstrap mode. Upgrade the control plane first, then roll the gateways.

Build and test from the repository root:

```sh
make build.porter
go test ./extensions/porter/...
docker build -f extensions/porter/docker/Dockerfile -t agentio-porter:dev .
```

## Metrics

Porter exposes metrics on `:9004/metrics`, configurable with `--metrics-port`. Prometheus scrapes Porter directly; gateway-agent and its 15020 endpoint are unchanged.

| Metric | Meaning |
| --- | --- |
| `agentio_porter_connect_duration_seconds{protocol="tcp\|udp"}` | Histogram from receipt of valid CONNECT headers through response send completion, including identity resolution, discovery waits and policy preparation |
| `agentio_porter_demand_cache_entries` | Current retained subscription entries across Workload and Sandbox, including in-flight lookups; zero when retention is disabled |
| `agentio_xds_client_connected` | ADS stream state: 1 when open, 0 when disconnected; does not imply synchronized or ready resources |
| `agentio_xds_client_demand_wait_duration_seconds` | Histogram of calls that actually waited for discovery, labeled by `resource_type` and `result` |
| `agentio_xds_client_demand_waiters` | Current waiting demand calls, labeled by `resource_type` |

CONNECT duration excludes waiting for the first gRPC message, Envoy-side processing and tunnel lifetime. Both successful and failed processing attempts contribute samples. The cache gauge reads the existing cache size at scrape time; it counts retained subscriptions, not necessarily ready resources, and adds no per-request tracking.

xdsclient owns the three discovery metrics and enables them when `Config.MetricsRegisterer` is non-nil; Porter supplies its registry. Other consumers can enable them the same way, without callbacks or a separate HTTP server inside xdsclient. Multiple clients sharing a registry must use distinct constant labels, for example `prometheus.WrapRegistererWith(prometheus.Labels{"client": "porter"}, registry)`.

The `resource_type` label is the configured watch's full TypeURL; no resource name or client identity is added. Wait results are `success`, `not_found`, `timeout`, `canceled` or `error`. Immediate results do not contribute duration samples. Concurrent calls for the same resource count separately, and their timers continue across reconnections. The histogram's `_count` can provide completion and timeout rates without a separate counter.

Deployments declare a container port named `porter-metrics`. For Prometheus Operator, apply [the optional Porter PodMonitor](../../manifests/charts/agentio/addons/porter-podmonitor.yaml) and ensure your Prometheus instance selects it. Narrow its namespace and Pod selectors as needed. A separate Porter deployment can use the same named port. Existing gateway Prometheus annotations alone do not collect this endpoint.

Without Prometheus Operator, add a separate scrape job:

```yaml
- job_name: agentio-porter
  kubernetes_sd_configs:
    - role: pod
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_container_port_name]
      action: keep
      regex: porter-metrics
    - source_labels: [__meta_kubernetes_namespace]
      target_label: namespace
    - source_labels: [__meta_kubernetes_pod_name]
      target_label: pod
```

The Agentio Grafana dashboard includes CONNECT mean/P95/P99 duration, retained cache entries, ADS connection state, demand wait P95/P99 duration and current demand waiters.
