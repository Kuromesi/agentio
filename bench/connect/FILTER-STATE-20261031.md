# Native gateway filter-state repair — 2026-10-31

## Behavior

Native `sandbox.id`, `sandbox.token`, workload name/namespace and both label fields now share `ONCE`. The TLS termination chain explicitly relays them once to `main_forward`. EPE and access logs retain readable values at the final internal listener, while external connection pools no longer include these business fields in their keys.

`agentio.workload.instance` is removed from filter state. Porter certificate-instance authentication is unchanged. The canonical `agentio.workload.labels` remains Hashable for internal context isolation; the identical `sandbox.labels` compatibility alias uses `envoy.string`. Legacy gateway generation and EPE label resolution are unchanged.

Making both label fields non-Hashable was rejected: with 24 concurrent CONNECT streams on one HTTP/2 connection, equal identity/token but differing label revisions reproduced cross-stream label contamination. Dedicated TCP tunnels do not eliminate the need to distinguish pending connection contexts in a shared pool. Keeping the canonical label in the internal key passed this regression.

## Validation

Isolated real Envoy processes on `ssh my-ecs`, using the generated authority/workload/relay filters and internal transport clusters. The fixture replaces TLS/Porter identity inputs with synthetic headers and observes all six values at the final HCM. Product labels still originate from WDS through Porter, not client headers.

Each case runs 300 serial requests and another 240 requests at concurrency 24. Cases alternate sandbox identities, label revisions, token changes, empty tokens and absent sandbox IDs. Final results have zero state mismatches. Both versions additionally pass 240 CONNECT streams multiplexed on one HTTP/2 connection.

| Envoy | Path | Baseline connections / 300 serial requests | Fixed |
|---|---|---:|---:|
| 1.39.4 | Internal HTTP → HTTP origin | 172 | 1 |
| 1.39.4 | TLS termination → HTTP origin | 243 | 1 |
| 1.40.2 | Internal HTTP → HTTP origin | 116 | 1 |
| 1.40.2 | TLS termination → HTTP origin | 131 | 1 |
| 1.39.4 | TLS termination → TLS origin | 236 | 1 |
| 1.40.2 | TLS termination → TLS origin | 131 | 1 |

These are single-run connection counts, not throughput benchmarks. The baseline is the branch before this filter-state change; it already includes the earlier xDS repairs.

Final-source `TestEnvoyPostTLSForwarding` passes on both binaries, covering raw TCP, nested TLS, certificate rejection, idle timeout, HTTP/1, HTTP/2 and application CONNECT over HTTP/1 and HTTP/2. Networking package tests, EPE attribute tests, formatting checks, incremental networking lint and `git diff --check` pass.

Repeat the retained integration suite with:

```sh
AGENTIO_TEST_ENVOY_BINARY=/path/to/envoy go test ./pkg/networking \
  -run 'TestEnvoyPostTLSForwarding|TestWorkloadStateTLSRelay|TestConnectIdentityFallbackTransfer' -count=1
```

Detailed replay scripts, configurations and results are retained on `my-ecs` in `/root/agentio-filter-state-20261031/verify`. Run `PYTHONPATH=vendor python3 verify.py /path/to/envoy` there for the HTTP-origin comparison; `verify_tls_origin.py` additionally enables TLS to the origin. Local evidence is in `/tmp/agentio-filter-state-20261031`.

## Limits

No Kubernetes rollout or new 24-hour soak. Porter/EPE discovery is not exercised by the synthetic state replay. H2 multiplexing checks use cleartext inner HTTP; TLS state checks use HTTP/1 CONNECT.

The initial replay fixture's inner `Connection: close` lost the response through TLS relay on both baseline and candidate. The retained state-isolation comparison uses keepalive and closes after reading the response. This baseline behavior is recorded separately and is not claimed fixed by the filter-state change. The fixture's original Python listen backlog of 5 also caused concurrent connection timeouts; final comparisons use backlog 128.
