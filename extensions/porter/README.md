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

Porter exposes its own Prometheus endpoint on `:9004/metrics`, configurable with `--metrics-port`. It does not rely on gateway-agent to scrape or merge metrics; gateway-agent's 15020 endpoint is unchanged. Both same-Pod and separate deployments can scrape Porter directly. This metrics endpoint does not change Porter's existing ADS authentication or deployment requirements.

| Metric | Meaning | Labels |
| --- | --- | --- |
| `agentio_porter_connect_duration_seconds` | Histogram from receipt of CONNECT headers through completion of the ext_proc response send; excludes waiting for the first message and tunnel lifetime | `protocol`, `result` |
| `agentio_porter_connect_requests_total` | Completed valid CONNECT processing attempts | `protocol`, `result` |
| `agentio_porter_connect_inflight` | CONNECT requests currently being processed | `protocol` |
| `agentio_porter_demand_duration_seconds` | Histogram of lookups that waited for discovery, including ADS reconnection time; immediate results are excluded | `resource_type`, `result` |
| `agentio_porter_demand_requests_total` | Completed demand lookups, distinguishing immediate results from calls that waited | `resource_type`, `path`, `result` |
| `agentio_porter_demand_waiters` | Number of demand calls waiting for a usable resource | `resource_type` |
| `agentio_porter_demand_pending_resources` | Distinct resource names with waiting calls | `resource_type` |
| `agentio_porter_demand_cache_entries` | Retained subscription leases across resource types, including in-flight lookups; zero when retention is disabled | None |

The protocol is `tcp` or `udp`. CONNECT results are `allow`, `deny`, `timeout`, `canceled` or `error`; allow means Porter permitted the CONNECT, not that the subsequent tunnel or TLS handshake succeeded. Demand results are `success`, `not_found`, `timeout`, `canceled` or `error`, with path `immediate` or `waited`. Resource types are `workload` and `sandbox`. Workload names, IPs, authorities and Sandbox IDs are not metric labels. Go runtime and process metrics are exposed in the same registry.

Demand has no FIFO queue: concurrent callers can share one subscription. Ten callers waiting for the same Workload produce ten waiters and one pending resource. The latency histogram measures caller-observed discovery wait, not control-plane processing or wire latency alone. CONNECT latency includes identity resolution, Workload/Sandbox lookup, policy preparation and response send; it does not include Envoy-side scheduling or network latency before Porter receives headers.

Deployments declare a container port named `porter-metrics`. For Prometheus Operator, apply [the optional Porter PodMonitor](../../manifests/charts/agentio/addons/porter-podmonitor.yaml) and ensure the Prometheus instance selects its labels and namespace. The example discovers that named port across namespaces; narrow `namespaceSelector` and `selector` for your installation. An independently deployed Porter can use the same port name. This is separate from the gateway's existing single-port Prometheus annotations: those annotations alone will not scrape Porter.

Without Prometheus Operator, add a separate Kubernetes pod-discovery scrape job:

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

The Agentio Grafana dashboard includes a Porter row with CONNECT rate, latency, in-flight requests, discovery wait latency, pending work and demand result rates. Its Porter panels use the independent metrics and do not require gateway metrics to exist.
