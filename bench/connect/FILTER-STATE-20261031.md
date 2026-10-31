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

## Follow-up: sandbox credential metadata

After integrating upstream `953f693a`, the newly introduced sandbox credential state is named `agentio.sandbox.metadata`. Its `X-AGENTIO-SANDBOX-METADATA` input remains unchanged. Capture and TLS relay both use Hashable + ONCE with `skip_if_empty=true`; EPE and both Helm templates use the new state name. Missing metadata retains the existing legacy `sandbox.token` fallback, while present invalid metadata does not fall back.

The replay was extended to seven fields and 24 identity/credential combinations, including changed access tokens, changed client IDs and absent metadata. Envoy 1.39.4 and 1.40.2 each passed the HTTP and TLS-termination paths: 300 serial plus 240 concurrent requests per path, zero state mismatches, and one external origin connection for each 300-request serial run. Each version additionally passed 240 multiplexed HTTP/2 CONNECT requests. Scripts and results are retained at `/root/agentio-sandbox-metadata-review` on `my-ecs`.

Networking, the full EPE suite, compiler/xDS/Store and Helm chart tests passed after integration, along with incremental lint. This is synthetic credential-state replay; it does not claim a live credential-provider authentication test.

## Remaining limits

No Kubernetes rollout or new 24-hour soak. Porter/EPE discovery is not exercised by the synthetic state replay. H2 multiplexing checks use cleartext inner HTTP; TLS state checks use HTTP/1 CONNECT.

The initial replay fixture's inner `Connection: close` lost the response through TLS relay on both baseline and candidate. The retained state-isolation comparison uses keepalive and closes after reading the response. This baseline behavior is recorded separately and is not claimed fixed by the filter-state change. The fixture's original Python listen backlog of 5 also caused concurrent connection timeouts; final comparisons use backlog 128.

## Repository replay and CI

The seven-field regression is now retained in [filter-state/verify.py](filter-state/verify.py) and [filter-state/h2_check.py](filter-state/h2_check.py). It reads the checked-in generated native gateway fixture, preserves the generated factories/sharing/relay settings, and replaces identity input with synthetic headers. It asserts all seven fields, including metadata changes/absence, and one external origin connection for 300 serial requests. The HTTP path also runs 240 CONNECT streams multiplexed on one HTTP/2 connection. Pool counts apply only to the serial phase; concurrent traffic is checked for state isolation.

`bin/test_gateway_runtime.sh` builds its [test image](filter-state/Dockerfile) from the selected gateway image and runs this regression in the existing gateway-runtime CI job. Dependencies are Python 3, python-h2 and OpenSSL. For an existing Envoy binary on a host with these dependencies:

```sh
python3 bench/connect/filter-state/verify.py /absolute/path/to/envoy --output /tmp/agentio-filter-state
```

The script creates a one-day localhost test certificate, writes bootstraps/logs/results under `--output`, and exits nonzero on a state mismatch or pool-reuse failure. Without `--output` it cleans its temporary files. There is no dependency on the original host's private fixture or certificate files. The runtime assertion always runs, regardless of the fixture filename. The historical TLS-origin comparison remains outside this retained regression.

The repository replay was rerun on my-ecs with Envoy 1.39.4 and 1.40.2; both passed every assertion. The [1.39.4 results](filter-state/results/envoy-1.39.4.json) and [1.40.2 results](filter-state/results/envoy-1.40.2.json) are retained. These runs use the current native golden fixture and generated localhost certificates.

The CI test image was also built from the pinned community Envoy 1.39.4 image and executed as UID 1337 on my-ecs; HTTP, TLS and H2 assertions passed. This verifies the added container entry point, not a rerun of the entire existing gateway-runtime job. Missing and explicitly empty filter state both format as an empty value here; the existing generated-config `SkipIfEmpty` assertions and EPE attribute tests cover metadata absence/fallback semantics.
