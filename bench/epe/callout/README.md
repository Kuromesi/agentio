# HTTPCallout test application and Envoy e2e

The standalone server implements EPE's HTTPCallout protocol using the production
`Invocation` / `Decision` types. It validates invocations, limits request JSON to
8 MiB, and never logs request bodies or credentials. It is a test application,
not an authorization service. Bind to loopback by default; use `-listen :18080`
only when a remote test proxy needs to reach it.

From the repository root:

```sh
go run ./bench/epe/callout/server -listen 127.0.0.1:18080
curl -sS http://127.0.0.1:18080/continue -H 'Content-Type: application/json' \
  -d '{"version":"0.1","phase":"request","request":{"method":"POST"},"policy":{"scope":"default/test","rule":"test","ordinal":0}}'
```

POST endpoints accept request- or response-phase invocations:

| Path | Behavior |
| --- | --- |
| `/continue` | Continue without mutation |
| `/mutate` | Set `x-callout-verdict: clean` and replace the phase's body with `changed by callout` |
| `/respond` | Return a local 403 with body `blocked by callout` |
| `/status` | HTTP 503 |
| `/malformed` | Truncated decision JSON |
| `/oversize` | Response larger than the default 1 MiB client limit |
| `/delay?duration=500ms` | Delay then continue; stop work on client cancellation (maximum 1 minute) |
| `/reset` | Close the HTTP/1 connection without a response |

GET `/healthz` checks readiness. GET `/stats` returns validated call count,
currently active calls, and calls canceled during delay. Counters do not retain
request data. Successful decision responses have protocol version `0.1`.

## Tests

```sh
go test -race ./bench/epe/callout/... \
  ./extensions/epe/pkg/filters/httpcallout ./extensions/epe/pkg/extensionprovider
```

Full e2e requires Linux with Docker host networking and a local Envoy image:

```sh
go test -v ./bench/epe/callout -run '^TestEnvoyE2E$' \
  -args -envoy-image envoyproxy/envoy:v1.39.4
```

The path is HTTP client → Envoy → real EPE ext_proc gRPC server → real provider
HTTP client → callout server; allowed traffic also reaches a real HTTP echo
upstream. EPE policy projection, engine, body buffering and mutations use
production code. The fixture injects a static policy resolver and synthetic
workload identity through Envoy filter state. It does **not** deploy agentiod,
Kubernetes, xDS policy distribution, TLS, or a production EPE main process.
Absent `-envoy-image`, Docker tests explicitly skip.

The e2e matrix covers both phases, fail-open/closed, all endpoint modes, exact
call counts (no silent identity bypass or retries), upstream reachability, header
and body mutations, and same-provider recovery after faults. Each invocation
creates a named temporary Envoy container and removes it on completion. Other
containers and clusters are untouched. Do not run concurrently with capacity
measurements on the same machine.

## Performance and stability

Reuse `bench/load` for scheduling and latency measurement. The full proxy chain
is exercised; the load generator, EPE, callout endpoint and echo upstream share
one Go process, while Envoy runs with two worker threads. Memory/goroutine/FD
samples describe that entire Go process, not isolated EPE memory. Latency includes
request creation, proxy round trip, response read and validation. Positive rates
also include scheduler queueing; zero rate uses closed-loop concurrency.

```sh
go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -timeout 15m -args \
  -envoy-image envoyproxy/envoy:v1.39.4 \
  -callout-concurrency 64 -callout-requests 30000 -callout-rate 1000 \
  -callout-rounds 10 -callout-body 1024
```

Each round must complete all requests, validate every expected response and
observe exactly one callout per request. `RESULT` JSON records throughput,
latency, error counts, per-second counts, post-GC heap, goroutines, FDs and active
callouts. Heap samples include measurement arrays retained for reporting; compare
rounds with identical sizes. A round has a 10-minute safety deadline; deadline
expiry fails instead of reporting a partial run as success. Body sizes are
0..1 MiB, with the fixture policy limit set to 2 MiB.

`-callout-path` selects `/request/<mode>/<open|closed>`,
`/response/<mode>/<open|closed>` or `/headers/<mode>/<open|closed>`.
`/baseline` keeps Envoy and EPE but resolves no callout rule.
Load validation supports unchanged echo bodies with HTTP 200, or an expected
non-200 status via `-callout-status` (e.g. 500 for fault/fail-closed).
Mutation and custom-response contents are checked by e2e, not the load mode.

For a remote host without Go, cross-compile locally and transfer these binaries
alongside `run.sh` to a dedicated remote directory:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/callout-server ./bench/epe/callout/server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/callout.test ./bench/epe/callout
```

`GOMAXPROCS=4 ENVOY_IMAGE=envoyproxy/envoy:v1.39.4 bash run.sh` runs the e2e,
concurrency/baseline matrix, 64 KiB and 1 MiB bodies in both phases, concurrent
fault loads, three 100,000-request baseline/callout pairs, and a 5-minute 1,000 RPS soak. It stops on a failure and retains raw
logs under `results/`. Keep those logs outside the source tree or in an ignored
local directory. To measure EPE CPU separately from network and fixture costs,
use the existing `BenchmarkCalloutCPUPath` in
`extensions/epe/pkg/filters/httpcallout`.

To compare forwarding headers alone versus headers plus body, add
`-callout-forward-headers`. This selects `headers.mode: all` and sends the same
16 synthetic request headers (each value 64 ASCII bytes), in addition to normal
HTTP/Envoy headers. Keep the original request body identical in both runs:

```sh
for phase in headers request; do
  GOMAXPROCS=4 go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -args \
    -envoy-image envoyproxy/envoy:v1.39.4 -callout-forward-headers \
    -callout-path "/$phase/continue/closed" -callout-body 1024 \
    -callout-concurrency 64 -callout-requests 100000
done
```

Without that flag, headers are not forwarded (`headers.mode: none`); the
`/headers/` route then sends only request metadata, without buffering a body.

## Isolated EPE measurements

Use `-callout-isolated` with `TestEnvoyLoad` to run the generator, EPE, callout
endpoint and echo upstream in separate processes. EPE CPU/RSS is then recorded
as `epe_cpu_seconds` and `epe_rss_bytes`; endpoint CPU/RSS is recorded as
`endpoint_cpu_seconds` and `endpoint_rss_bytes`. The heap/goroutine/FD fields
still describe the load-generator process. In the default shared mode those
per-process CPU/RSS fields are zero. The fixture allocates GOMAXPROCS 4 to EPE, 8 to the
endpoint and 4 to upstream; set the parent process's GOMAXPROCS separately.

```sh
GOMAXPROCS=4 go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -timeout 15m -args \
  -envoy-image envoyproxy/envoy:v1.39.4 -callout-isolated \
  -callout-forward-headers -callout-body 1048576 \
  -callout-concurrency 64 -callout-requests 10000
```

`-callout-process-artifacts /absolute/directory` retains each child's logs and
CPU profile (with profiling overhead). Without it, child logs are temporary.
All child processes and the test Envoy are stopped after the test.
