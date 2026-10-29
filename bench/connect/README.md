# CONNECT data-plane benchmarks

Go tools for repeatable Envoy HTTP/2 CONNECT throughput and resource measurements. The traffic generator supports upload/download, shared or distinct sandbox identities, and one fast sandbox beside a throttled sandbox. The runner creates a fresh Envoy and TCP origin for each case, pins their CPUs separately, saves configuration and logs, and emits JSONL.

This is a synthetic plaintext loopback fixture. Test-only request headers populate trusted filter state; it does not run the production identity, mTLS/SDS or Agentio control-plane chain. HTTP/TLS payload interpretation is deliberately absent: the fixture measures TCP payload bytes inside CONNECT.

## Reuse of existing bench infrastructure

- `load/` uses [`bench/load`](../load/README.md) to schedule CONNECT establishment and measure its latency. Established tunnels outlive the setup scheduler; byte throughput is measured separately after warmup. Operation QPS is not used as a substitute for sustained byte throughput.
- `run/` follows the existing Porter/xDS `run` / `analyze` CLI and artifact-directory pattern. Their scenario-specific Kubernetes controllers are not duplicated or coupled into this local data-plane runner.
- The Go origin and load binaries accept listener addresses and process IDs, so they can be run separately in a shared Linux process namespace. The same runner image works in Docker or a disposable Kubernetes Pod.
- Functional regression tests remain in `extensions/envoy/network-limits/tests`; the tests and benchmark share the versioned Envoy bootstrap in `fixture/bootstrap.json`, modified by Go for each case.

## Build

Use the Go toolchain specified by the repository's `go.mod`. From the repository root:

```sh
CONNECT_BENCH_BUILD="$(mktemp -d /tmp/agentio-connect-build.XXXXXX)"
mkdir -p "$CONNECT_BENCH_BUILD/bin"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$CONNECT_BENCH_BUILD/bin/connect-load" ./bench/connect/load
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$CONNECT_BENCH_BUILD/bin/connect-bench" ./bench/connect/run
```

Change `GOARCH` to the Linux host architecture. Build the Rust module on Linux using its [build instructions](../../extensions/envoy/network-limits/README.md), then build the runtime and benchmark images:

```sh
docker build --target runtime -t agentio-network-limits:runtime extensions/envoy/network-limits
docker build -f bench/connect/Dockerfile -t agentio-connect:bench "$CONNECT_BENCH_BUILD"
```

`--build-arg BASE_IMAGE=...` selects another image containing compatible Envoy and module binaries. Runtime requirements are Linux `/proc` and CPU topology, `taskset`, and `getconf`; Python is not required. The runner needs eight available **physical cores** and fails if fewer are available. Affinity does not reserve cores against other host workloads. Avoid CPU quotas for capacity comparisons.

## Run

Keep generated binaries, logs, raw results and reports outside the repository. Use a new output directory for each invocation; the runner refuses nonempty directories. Ports `base-port` through `base-port+3` must be free in the container/process network namespace.

```sh
CONNECT_BENCH_RESULTS="$(mktemp -d /tmp/agentio-connect-results.XXXXXX)"
docker run --rm --memory=3g --pids-limit=2048 \
  -v "$CONNECT_BENCH_RESULTS:/results" agentio-connect:bench \
  run -suite=pilot -repeats=1 -warmup=1s -duration=2s -output=/results/pilot
```

The default run uses three repeats, two seconds of warmup and six seconds of measurement, in a reproducible shuffled order:

| Suite | Cases per repeat | Coverage |
| --- | ---: | --- |
| `bandwidth` | 19 | Download 1/32/256 streams: baseline, bypass, high, shared, distinct; upload 32 streams: all except bypass. |
| `capacity` | 11 | Unbounded baseline/bypass/high cases with exact worker connection balancing. |
| `isolation` | 3 | One fast sandbox beside 0/32/256 noisy streams; exact worker connection balancing. |
| `pilot` | 4 | 32-stream download: baseline, high, shared, distinct. |

Modes:

- `baseline`: no bandwidth filter; identity extraction stays enabled.
- `bypass`: module installed with an unmatched descriptor.
- `high`: shared 1 TiB/s byte budget, intended to measure nonbinding accounting overhead.
- `shared`: all streams share a 32 MiB/s budget.
- `distinct`: each stream has its own budget; configured rates total 32 MiB/s.
- `isolation`: noisy streams share 32 MiB/s; the last stream has a distinct 1 TiB/s download budget.

For concurrency-filter overhead, run the same suite twice with and without `-concurrency-limit=1024`, each into its own output directory. A positive value installs the independent concurrency filter in **every case, including baseline**. Choose a nonbinding limit for overhead comparisons: rejected CONNECTs fail the benchmark rather than count as successful throughput. This option does not implement a rejection/churn load scenario. Native CONNECT creation-rate limiting is not installed by these suites.

Other runner flags: `-envoy`, `-load`, `-module`, and `-base-port`. These allow different compatible binaries and port ranges without changing source. `connect-load -h` documents standalone generator arguments, including outer connection count, target address, origin counters and setup timeout. All runner suites use at most four HTTP/2 connections and two Envoy workers.

For Kubernetes, use the same image and command in a `restartPolicy: Never` Pod with a writable output volume and enough unquotaed CPU availability. Retain logs and output before removing its disposable namespace. The runner manages its child processes, not cluster resources; follow the existing bench convention of an explicit kubeconfig/context for deployment and cleanup.

## Results and interpretation

The runner writes:

- `results.jsonl`: environment row followed by validated measurements; also streamed to stdout.
- `config.json`: runner parameters.
- One directory per case containing `envoy.json`, `envoy.log`, `origin.log`, `load.log`, and `result.json`.
- `failure.txt` on failure. A partial result file is not a completed suite; check exit status and the last row's `case`/`total`.

Analyze results on any Go-supported development host:

```sh
go run ./bench/connect/run analyze "$CONNECT_BENCH_RESULTS/pilot/results.jsonl"
```

The summary reports medians and throughput ranges across repeats. Raw rows retain per-stream minimum/median/maximum throughput and, for isolation, separate `fast_mib_per_s` and `noisy_mib_per_s`; inspect these when checking starvation or cross-sandbox effects.

Download bytes are counted at the client; upload bytes at the origin. Process CPU comes from `/proc/<pid>/stat`, normalized using the host's `CLK_TCK`; `1.0` means one fully used core. Envoy RSS is sampled every 100 ms. CPU assignments remain two physical cores for Envoy, four for the generator and two for the origin.

`connect_p50_ms` and `connect_p95_ms` now use the shared Go scheduler's latency/quantile convention and describe establishment, not application latency. Environment rows have `schema_version: 2`. Historical JSONL from the previous Python runner is kept outside the repository along with other run artifacts. Byte-rate/CPU/RSS field units are retained, but the Go seeded shuffle and setup percentile calculation are not identical to that runner. The analyzer also reads those historical rows.

These short synthetic tests do not establish real-NIC capacity, outer mTLS overhead, long-term memory stability, connection churn, production identity costs, or multi-replica quota behavior. Shared bandwidth budgets still do not promise scheduling fairness.

Generated output is intentionally not versioned. Preserve the external output directory when sharing a run; the source tree contains only tools, input fixtures, tests and documentation.

## Checks

```sh
go test -race ./bench/load ./bench/connect/...
```

Unit tests cover scenario counts, configuration variants, CPU/stat parsing, upload counting, historical-result analysis, and tunnel survival after the shared setup scheduler finishes. Validate actual binaries with `pilot` on Linux; use `capacity` for both upload and download and `isolation` for mixed tenants.
