# Network limits dynamic module

Currently, this Rust HTTP dynamic module provides independent bandwidth and concurrency filters for CONNECT tunnels. Install them after trusted identity filters and before the router on `connect_terminate`. HTTP, TLS and other TCP payloads consume the same byte budget; inner TLS records count as bytes. Outer HBONE headers, HTTP/2 framing, outer TLS and IP overhead do not count. No Envoy source changes are needed.

`src/lib.rs` registers both filters. `src/bandwidth/` and `src/concurrency/` each contain their implementation in `mod.rs` and unit tests in `tests.rs`; `src/descriptor.rs` contains their shared descriptor matching and validation. The library is named `envoy_agentio_network_limits`; the individual filter names remain `envoy_agentio_bandwidth` and `envoy_agentio_connect_concurrency`. CONNECT establishment rate limiting still uses Envoy's native filter.

The gateway image includes `libenvoy_agentio_network_limits.so`. Enable it with `egressGateways[].bandwidthLimit` in [AgentioConfig](../../../docs/reference/agentio-configuration.md#connect-bandwidth-limits); see the [configuration example](../../../manifests/examples/gateway-bandwidth-config.yaml). The controller generates the filter placement, module path and stable `agentio/<namespace>/<name>/bandwidth` budget name. Gateway API parameters use the same settings. Do not derive production identity from arbitrary client headers. The module targets the community Envoy gateway, not legacy proxyv2.

Enabling either network limit publishes only the community Envoy resource variant for that gateway. Upgrade all legacy proxyv2 instances before enabling these limits; their old listener resources are withdrawn rather than forwarding traffic without enforcement. Initial filter installation also requires existing community Envoy HBONE connections to drain: new CONNECT streams on those pooled connections can still use the old filter chain until draining completes. A config dump showing the new filters does not mean every connection is already limited. Subsequent quota updates share the existing module budgets and do not require this drain.

## Independent concurrency filter

The same library also registers `envoy_agentio_connect_concurrency`. Enable it independently with `egressGateways[].connectConcurrencyLimit`; see the [configuration and lifecycle contract](../../../docs/reference/agentio-configuration.md#connect-concurrency-limits) and [combined example](../../../manifests/examples/gateway-concurrency-config.yaml). Agentio installs it after native CONNECT rate limiting and before bandwidth shaping. The concurrency filter uses the same descriptor matcher but has its own registry; it creates no scheduler or buffering state.

For direct module configuration, use `filter_name: envoy_agentio_connect_concurrency`, keep `dynamic_module_config.name: envoy_agentio_network_limits`, the same library path and `do_not_close: true`. Its JSON has `budget_name` (default `default`), `rate_limits`, `descriptors` and `max_dynamic_buckets` (default 10000). Each descriptor contains `entries` and positive numeric uint32 `max_concurrent_streams`; byte rates and buffer watermarks are not accepted. Limits and dynamic capacity can update in place; grouping changes require draining the old configuration. Standalone callers choose a shared budget name; Agentio generates `agentio/<namespace>/<name>/connect_concurrency`.

`tests/concurrency_test.go` checks both concurrency-only and all-three-filter chains with two workers: shared sandbox and gateway totals, request half-close, normal completion, reset, connection loss, upstream failure, LDS limit changes and rejected-candidate rollback. Run it using:

```sh
./bin/test_network_limits.sh agentio-network-limits:test
```

## Bandwidth module configuration

The module parses the JSON representation of `filter_config` (`google.protobuf.Struct`); these fields are not a new Agentio CRD or the native Envoy rate-limit protobuf. Descriptor terminology follows Envoy's local rate-limit configuration:

```yaml
budget_name: sandbox-bandwidth
rate_limits:
  - actions:
      - filter_state: {key: tenant.id, descriptor_key: tenant}
      - filter_state: {key: sandbox.id, descriptor_key: sandbox}
descriptors:
  - entries:
      - {key: tenant}
      - {key: sandbox}
    bandwidth_limit:
      upload_bytes_per_second: 10485760
      download_bytes_per_second: 52428800
max_dynamic_buckets: 10000
buffer_limit_bytes: 65536
```

- Each action group produces one ordered descriptor. All entries form a composite key: `(tenant=A, sandbox=X)` is independent of `(tenant=B, sandbox=X)`. A `generic_key: {descriptor_key: ..., descriptor_value: ...}` action adds a fixed entry.
- Entries with omitted or empty `value` are wildcards: every distinct actual value combination gets its own budget. Nonempty `value` matches exactly. Full exact descriptors take priority; otherwise the first matching wildcard descriptor wins. Prefix matching is not supported.
- Multiple action groups can apply simultaneously, for example a tenant-wide budget and a tenant/sandbox budget. All applicable budgets must permit a batch before any are charged; duplicate matches are charged once.
- Upload means downstream to upstream; download means upstream to downstream. Directions have independent budgets. Rates are positive integer **bytes per second** (numbers or ProtoJSON uint64 strings). An omitted direction is unlimited; zero and a descriptor with neither rate are invalid.
- Required filter state is read once at request headers, using its serialized UTF-8 string. Missing, empty or unserializable values reject the request with 403. Complete descriptors with no match are unlimited. Include a wildcard descriptor when every key must be limited.
- Unknown configuration fields, duplicate descriptors and entries that do not match an action group's ordered keys reject configuration loading.

## Sharing, buffering and lifecycle

For standalone module configuration, `budget_name` defaults to `default`. All filter instances with the same name in the loaded module share budgets across workers, listeners and connections in one Envoy process. Different replicas/processes do not share budgets. Use the same module path and `do_not_close: true`, as generated by Agentio, to retain the registry through configuration replacement.

Rate changes reuse the existing buckets. Remaining debt in bytes is preserved and converted to time at the new rate; waiting streams are notified on their workers. Omitting a direction makes it unlimited; previous debt continues expiring at its last rate so a quick rollback cannot refill the bucket. The newest live Envoy configuration supplies rates and capacity, including for streams using older filter configurations. Destroying a rejected candidate restores the preceding live configuration. This happens at module construction/destruction, not at an LDS ACK boundary: a warming candidate may affect rates temporarily, and this is not an atomic multi-resource update.

Actions and descriptor entries/order must remain unchanged while the budget is in use. To change grouping, drain/remove the old configuration and wait for unpaid debt before loading the new layout. Changing the budget name deliberately creates a separate budget. Removing the filter leaves existing streams using their original filter until they close. Watermark changes affect streams created from the new filter configuration.

`max_dynamic_buckets` defaults to 10000 and bounds wildcard-derived buckets per budget name, across descriptor rules. Active buckets and buckets with unpaid byte debt cannot be evicted. A new distinct key that exceeds capacity receives 503. Lowering capacity preserves existing buckets and blocks new keys until capacity is available. Reconnecting never resets outstanding debt. Explicit exact descriptors do not consume this dynamic capacity.

The module forwards a batch when its budgets are ready, then charges `batch_bytes / rate` before the next batch. Envoy owns the buffered bytes. A waiting stream returns `StopIterationAndWatermark`; a timer thread posts callbacks to the owning worker to resume it. Cancellation removes pending timers. Both directions use Envoy's streaming watermarks for source backpressure.

`buffer_limit_bytes` defaults to 65536 and sets the stream's **soft watermark**, not a hard allocation or burst cap. The callback batch size depends on Envoy, transport buffers and other filters. Short transfers can pass in the first batch; subsequent traffic, including reconnects, pays for it. The sustained cap is per key; scheduling does not promise fairness between streams, minimum bandwidth, CPU isolation or global link capacity allocation. Choose limits whose aggregate fits the available link.

Supported placement is the TCP CONNECT chain, immediately before the router and after trusted identity processing. **Do not enable router retries on this chain**, including route/virtual-host retry policies or retry-policy extensions. The module rejects `x-envoy-retry-on` and `x-envoy-retry-grpc-on` headers that reach it with 400 (`bandwidth_retry_unsupported`). Do not combine it with internal redirects, buffered request mirroring, or other filters that retain already-forwarded body data in the shared filter-manager buffer: resuming that buffer can send those bytes again. Agentio's generated CONNECT route has no retries; retries on the separate inner HTTP chain are unaffected. Manual gateway patches must preserve this restriction; the module cannot inspect route retry policies through the current ABI.

CONNECT-UDP, separately configured upgrade filter chains, and traffic bypassing this listener are outside this integration. The current HTTP dynamic-module ABI lacks the partial data-injection and source-watermark callbacks used by Envoy's native bandwidth filter, so this module retains batch pacing rather than a strict burst cap.

**Envoy v1.39.4 limitation:** when a raw TCP upstream closes first while the HTTP/2 CONNECT request remains open and the response is blocked by the downstream HTTP/2 window, Envoy can reset the stream before delivering its final bytes. This also reproduces without this module. The runtime option `allow_multiplexed_upstream_half_close` does not fix the TCP-upstream case. The HTTP/2 transfer tests half-close the request after sending its payload; the HTTP/1 tests exercise upstream-first closure. Validate this close pattern with your actual HBONE client before production deployment; this module does not fix Envoy's CONNECT close semantics.

## Build and test

On Linux, install Rust 1.93+, Go (the version in `go.mod`), clang/libclang, curl, tar and Docker. Run from the repository root:

```sh
bash extensions/envoy/network-limits/build.sh
docker build --target runtime -t agentio-network-limits:test extensions/envoy/network-limits
./bin/test_network_limits.sh agentio-network-limits:test
```

`build.sh` checks formatting, runs Rust tests and builds the shared library. The SDK is pinned to Envoy commit `b579d07d3ad7ee11d32b105e91a5a39ad24718d7`, matching the repository's Envoy v1.39.4 image. Remove `.envoy-sdk` when changing the pin; the dynamic-module ABI must match the Envoy binary.

`bin/test_network_limits.sh IMAGE` builds a Go test binary in a temporary directory outside the repository and runs it as the gateway user against the given image. The image build workflow runs it on both native architectures before recording the candidate digest. No Python or OpenSSL executable is required.

The real-Envoy fixture runs two workers with local TCP/TLS origins and HTTP/1 CONNECT plus multiplexed HTTP/2 CONNECT clients. Test-only headers populate filter state. It checks aggregate upload/download, full-duplex resumption, retry-header rejection, independent composite keys, a fast stream beside a limited stream, shared HTTP/TLS budgets, missing identity, HTTP/2 half-close, source backpressure, Envoy RSS growth and cancellation. A Rust regression test ensures request resumption returns without touching the filter again and leaves the response scheduled; configuration tests keep inner HTTP retries off the outer CONNECT route. File-based LDS updates verify speed increases/decreases on an existing tunnel and rollback when a later filter rejects a candidate. Go tests cover watched AgentioConfig updates through generated xDS listeners, both configuration entry points, and TCP-only placement. Production identity discovery, mTLS/SDS and the full Agentio deployment require separate end-to-end testing.

## Performance benchmarks

Reusable Go load generation, Envoy/origin orchestration and result analysis live under [`bench/connect`](../../../bench/connect/README.md). Store generated binaries, logs, results and reports outside the repository. The benchmark supports bandwidth-only and combined concurrency/bandwidth comparisons and has no Python runtime dependency. The Go tests in this module share `bench/connect/fixture` with the benchmark.
