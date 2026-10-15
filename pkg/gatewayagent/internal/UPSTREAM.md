# Maintained pilot-agent extraction

Source baseline: `openkruise/agentio`, `release-0.1`, commit `169bad3c36783711989757cd907465b8fe9cfc3a`. Original code is Apache-2.0; copyright notices are retained. These are local sources, not an Istio Go library dependency. The gateway binary must have no `istio.io/*` package in its dependency tree, including indirect imports.

| Local code | Source and changes |
| --- | --- |
| `envoy/agent.go`, `envoy/proxy.go`, `envoy/admin.go` | Copied from `pkg/envoy`. Replace Istio logging, collections, HTTP and environment helpers with standard-library implementations. Remove FIPS, bootstrap overrides and permissive unknown-static-field handling. Bound Admin requests, reap the child on kill/skip-drain, and bound the optional active-connection drain loop. |
| `envoy/ready.go`, `envoy/stats.go` | Copied from `pilot/cmd/pilot-agent/status/ready/probe.go` and `status/util/stats.go`. Preserve initial CDS/LDS and LIVE/workers checks. Remove Istio startup metric and helper dependencies. |
| `../identity.go` | Adapt the `security/pkg/nodeagent/cache/secretcache.go` CSR/cache/rotation responsibilities and `caclient/providers/citadel/client.go` signing protocol. This is a reduced implementation, not a verbatim copy of the complete secret cache. Retain locally generated keys, SPIFFE CSR and actual certificate expiry; default to RSA-2048, 50% rotation grace and 1% jitter, with configurable key and renewal parameters. Use Go `crypto/x509`; reload token and roots per signing attempt, bound retries, validate returned identity/key/chain, and retain a valid cached certificate during CA failure. |
| `../sds.go` | Adapt `security/pkg/nodeagent/sds/sdsservice.go` resource generation and watch/push behavior. Replace the generic Istio xDS framework with a bounded SotW stream loop for `default` and `ROOTCA`; reject arbitrary file and domain secret requests. Local SDS remains SotW, as in pilot-agent. |
| `caproto/ca.proto`, generated Go | Vendor the CA wire schema from `istio/api` commit `f9b16f1f49ce`, the API dependency of the release baseline. Preserve protobuf service/message names for compatibility with agentiod. The local Go package owns the implementation; no Istio API Go import is used. |

Additional intentional differences:

- Projected workload trust roots come from the mounted ConfigMap or ClusterTrustBundle, not `istio.mesh.v1alpha1.ProxyConfig` discovery. A one-second poll follows projected-volume symlink swaps independently of CA signing requests. A signing attempt has a ten-second deadline. Malformed/missing replacements retain the last valid bundle. Root changes trigger renewal and an SDS push.
- Only Pod-token authentication and the existing CA signing protocol are retained. No cloud credential plugins, arbitrary file SDS, output-certificate files, private-key providers, CRL discovery, external SDS delegation or mesh bootstrap.
- `../xds.go` is an Agentio transparent ADS relay, not a copy of pilot-agent's generic proxy with DNS, Wasm download/config rewriting, health and trust-bundle subscription processing. Native Envoy Wasm/ECDS remains available. The relay retains the release baseline's gRPC keepalive defaults without importing its helpers.
- SDS and ADS stay alive until Envoy drain and process cleanup finish.

When updating from pilot-agent, review upstream fixes to these source paths and port applicable fixes explicitly. Do not restore a whole-agent dependency.

Regenerate the local CA message code with `protoc-gen-go v1.36.11`, staging `ca.proto` at `security/v1alpha1/ca.proto`, and passing `--go_opt=module=github.com/openkruise/agentio`. The vendored gRPC stubs retain the unchanged service definition. Protocol compatibility does not require importing the original Go module.

Deployment configuration:

`AGENTIO_GATEWAY_CONFIG` accepts the locally maintained options below. Explicit JSON fields take precedence over defaults, followed by CLI flags. Metadata retains the existing `AGENTIO_META_*`/`AGENTIO_METAJSON_*` semantics. The agent does not parse Istio `PROXY_CONFIG`.

| Options | Behavior |
| --- | --- |
| `statsFlushInterval`, `statsEvictionInterval` | Go duration strings. Eviction must be a positive multiple of flush; omit eviction to retain the Envoy default. CLI equivalents are `--stats-flush-interval` and `--stats-eviction-interval`. |
| `statsMatcher` | `inclusionPrefixes`, `inclusionSuffixes`, `inclusionRegexps` arrays. Required readiness and drain metrics are retained. `{pod_ip}` expands over `instanceIPs`. |
| `extraStatTags`, `histogramBuckets` | Additional Istio-style encoded metric tags and a map of metric prefixes to ordered nonnegative bucket boundaries. |
| `runtimeValues`, `maxDownstreamConnections` | Native runtime keys and a global downstream connection resource monitor. Empty string/null removes a default runtime key. Health and metrics listeners bypass overload management. |
| `skipDeprecatedLogs`, `statsCompression` | Both default true. The former sets the Envoy flag (also `--skip-deprecated-logs`); the latter negotiates gzip for the complete combined metrics response, without buffering the full scrape. |
| `adminPort`, `statusPort`, `envoyStatusPort`, `prometheusPort`, `workloadSocket` | Default to 15000, 15020, 15021, 15090 and the standard workload SDS socket. Nondefault ports must be reflected in deployment probes and monitoring. |
| `instanceIPs`, `locality` | IP array starting with `INSTANCE_IP`; both families create additional health/metrics addresses. `locality` uses Envoy Node locality JSON (`region`, `zone`, `sub_zone`). |
| `metricsLocalhostOnly`, `statusProxyProtocol` | Restrict the Envoy metrics listener to loopback, or require PROXY protocol on the Envoy status listener. The latter requires a compatible health checker. |
| `xdsHeaders`, `caHeaders` | Lowercase ASCII gRPC headers. Authentication, cluster ID and gRPC-reserved headers cannot be overridden. |
| `rsaKeySize`, `eccCurve`, `pkcs8`, `certSigner`, `rotationGraceRatio`, `rotationJitter` | RSA 2048/3072/4096 or ECDSA P256/P384, optional PKCS8 and CA signer selection. Rotation defaults remain 0.5/0.01; expiry comes from the actual certificate. |
| `telemetryClusters` | Array of native Envoy Cluster JSON, including native TLS and HTTP/2 settings, for tracing/ALS/metrics backends. Duplicate or agent-owned names are rejected. Dynamic xDS can reference these clusters. |
| `statsSinks`, `tracing`, `loadStatsConfig`, `outlierEventLog` | Native Bootstrap stats sink array, tracing object, ClusterManager ApiConfigSource for LRS, and outlier event log path. StatsD, metrics service and tracing use the Envoy types directly; ALS filters remain in dynamic xDS. No Istio API translation layer is required. |
| `profiling` | Opt-in local-only pprof endpoints on the agent status port. `/metrics` aliases `/stats/prometheus`. |

`AGENTIO_ROOT_CA` is the workload trust bundle. `AGENTIO_XDS_ROOT_CA` and `AGENTIO_CA_ROOT_CA` independently select the TLS roots for the control-plane and signing connections, falling back to that bundle. These files are reread on new streams/signing attempts. Worker concurrency can be derived from `AGENTIO_CPU_LIMIT`.

Drain defaults are 20s for Envoy and 25s for process termination. Explicit JSON/CLI durations override these defaults and the existing Pod termination-grace cap still applies.

Example statistics and resource configuration:

```json
{
  "statsFlushInterval": "5s",
  "statsEvictionInterval": "1m",
  "statsMatcher": {"inclusionPrefixes": ["http.", "cluster."]},
  "histogramBuckets": {"http.": [1, 5, 10, 50, 100, 500]},
  "maxDownstreamConnections": 10000,
  "statsCompression": true
}
```

Telemetry resource objects are validated using Envoy protobuf JSON and the selected image must provide the referenced factories. They are configuration, not arbitrary bootstrap overrides: callers cannot replace the agent-owned ADS/SDS/health resources. Runtime tests validate configured resources against the pinned community Envoy binary; unsupported factories fail explicitly.

The gateway agent supports only the community Envoy bootstrap and `agentio-egress/<namespace>/<pod-uid>` node IDs. Existing pilot-agent deployment arguments, Istio annotations and legacy environment aliases are not supported; deployments must explicitly wire the agent configuration and credentials. Existing gateway deployment defaults are not switched.

`gateway-agent wait --port <statusPort>` waits on a nondefault agent status port. Deferred traffic statistics creation is enabled; configuring LRS or outlier logging also enables deferred worker cluster creation, matching the extracted bootstrap behavior.


With `metricsLocalhostOnly`, both the Envoy metrics listener and the agent's `/metrics` and `/stats/prometheus` endpoints accept only loopback clients; readiness probes remain reachable. The agent exposes `agentio_gateway_agent_envoy_scrape_success` and `agentio_gateway_agent_envoy_scrape_failures_total` in the same scrape, including when Envoy admin is unavailable. Scrape failures are also logged.

The runtime CI test launches the gateway-agent executable with community Envoy and verifies CA issuance, live SDS certificate rotation, readiness withdrawal on SIGTERM, ADS/SDS availability while draining, completion of an in-flight request, and child process reaping.
