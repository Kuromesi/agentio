# Fake xDS client and load scenarios

`fakeclient` is a small, caller-driven **Delta ADS** client. It accepts arbitrary resource type URLs and has no dependency on Sandbox/TrafficPolicy schemas, Pod identity conventions, Kubernetes, or the load runner. Each `Open` creates an independent gRPC connection and stream. The caller controls subscriptions, response validation, ACK/NACK timing, disconnects and reconnects.

The `scenario/` packages implement pluggable client behavior and Kubernetes drivers. The application under `load/` manages connections, replies and samples; the Go application under `run/` manages load Pods, connection stages, timing, reports and cleanup against an **existing** Kubernetes control plane:

| Scenario | Behavior |
| --- | --- |
| `discovery` | Subscribe to configurable type URLs, ACK responses, measure staged connection readiness, optionally hold the connections. |
| `trafficpolicy` | Bind one manual Sandbox per load Pod, subscribe to four Agentio resource types, and update a shared GlobalTrafficPolicy at each connection stage. Validate every rule's action, protocol and port, resource versions, complete sample coverage, and absence of redundant Sandbox pushes. |

The runner creates a unique namespace for each run; the TrafficPolicy driver also creates a uniquely named GlobalTrafficPolicy. It deletes its own resources on success, failure or interrupt. Namespace deletion is asynchronous. `--keep-resources` leaves the Pods/connections running; `cleanup.json` records their names and kubectl context for manual deletion. It never modifies control-plane resource limits, environment variables or images. Ctrl-C and SIGTERM cancel active work; cleanup runs with a separate deadline, checks run ownership and uses UID preconditions. A failed run retains both the original error and any cleanup errors in its artifacts.

## Add a scenario

```text
scenario/
  scenario.go                 # client contract
  decode.go                   # strict scenario-option decoding
  driver/driver.go            # Kubernetes driver contract and cleanup tracking
  discovery/
    client.go                 # configurable subscriptions and readiness
    driver/driver.go          # runner options and client configuration
  trafficpolicy/
    client.go                 # policy/Sandbox validation and round matching
    driver/driver.go          # resource creation, updates and cross-client checks
```

Implement a client package under `scenario/<name>` and add its constructor to the switch in `load/scenarios.go`. The factory receives `--scenario-config` JSON and returns a `ClientFactory`. Its `New` function creates a separate `Client` for each ADS stream; its optional `PrepareRound` function parses expected round parameters once per load process. Factories hold immutable configuration, and the prepared round value is shared read-only; mutable response/readiness state belongs to each client.

A client exposes `Subscriptions()` and `Observe(response, expected)`. `Observe` decides readiness, ACK/NACK/no reply, and whether the response completes the current round. Return a sample only for a successfully validated response that should be ACKed; the load loop submits that ACK and fills in the client ID and timestamps. The load loop discards samples from observations started before the latest round was armed. Each scenario must also match arriving responses against the expected round, for example using a unique marker or resource version.

For Kubernetes automation, implement `scenario/<name>/driver` and add its constructor to the switch in `run/scenarios.go`. The driver implements `ClientConfig`, `Prepare`, `Rounds`, `Trigger` and `Check`: generate per-Pod client options, prepare resources, enumerate opaque round parameters, trigger an update and validate the resulting client statuses. `Rounds` returning an empty list supports discovery/connection-only scenarios. Each runner gets a fresh driver instance; the load loop and orchestration logic use the shared interfaces.

`driver.Environment` provides Kubernetes clients, the run namespace and Pod names. Namespace deletion covers resources within the run namespace. Before attempting to create an extra cluster-scoped resource, call `Track` and label it with `driver.RunLabel: environment.Namespace`; tracking before the request ensures cleanup can find an object even if creation persists but its response is canceled. The runner checks that label and uses UID preconditions before deletion. Tracked resource references are included in `cleanup.json`.

Keep Kubernetes imports in the driver subpackage: `load` imports only client factories and therefore does not pull client-go into the load binary. The two entry points select constructors explicitly and reject unknown scenario names. Scenario-specific options go through `--scenario-config`, with misspelled JSON fields rejected by each factory.

| Scenario | Runner `--scenario-config` | Direct load application `--scenario-config` |
| --- | --- | --- |
| `discovery` | `{"types":["type.googleapis.com/istio.workload.Address"]}` | Same options as runner. |
| `trafficpolicy` | `{"rules":50,"ports_per_rule":[1,20]}` | `{"policy_name":"trafficPolicies/example","sandbox_id":"example--client-0"}` |

Defaults are the values shown in the runner column. The runner derives TrafficPolicy client resource names from its own run namespace and Pod names. Shared flags such as `--stages`, `--rate`, `--rounds` and `--ack-delay` stay in the runner. The old `--types`, `--rules`, `--ports-per-rule`, `--policy-name` and `--sandbox-id` flags are replaced by scenario JSON.

## Reuse the transport client directly

```go
import (
    "context"
    "time"

    core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    "github.com/openkruise/agentio/bench/xds/fakeclient"
)

func simulate(ctx context.Context) error {
    tlsConfig, err := fakeclient.TLSFromCA("root-cert.pem", "agentiod.example.svc")
    if err != nil { return err }
    client, err := fakeclient.Open(ctx, fakeclient.Config{
        Target: "agentiod.example.svc:15012",
        TLSConfig: tlsConfig,
        Token: fakeclient.FileToken("token"), // optional; refreshed on each Open
        Node: &core.Node{Id: "test-client"}, // add the identity metadata your server requires
    })
    if err != nil { return err }
    defer client.Close()

    typ := "type.googleapis.com/example.Resource"
    if err := client.Subscribe(typ, "*"); err != nil { return err }
    response, err := client.Recv()
    if err != nil { return err }
    // Inspect Resources/RemovedResources and intentionally model client behavior.
    select {
    case <-time.After(100*time.Millisecond):
    case <-ctx.Done(): return ctx.Err()
    }
    if err := client.NACK(response, "intentional scenario rejection"); err != nil { return err }
    return client.Unsubscribe(typ, "*")
}
```

Use `ACK(response)` for a valid response. Use `Send(DeltaDiscoveryRequest)` to supply initial resource versions, custom subscribe/unsubscribe sets or nonce behavior. `Headers`, `TLSConfig` (including client certificates) and `DialContext` allow alternate authentication and transport instrumentation. Explicit `Plaintext: true` is available for local plaintext test servers.

There is no automatic ACK, resource cache or stream reconnect. To test a reconnect, close the client and call `Open` again, optionally sending cached versions in the first request. A scenario should supply a bounded/cancellable context. One receiver and concurrent serialized sends are supported. gRPC may retry initial transport establishment; stream receive errors are returned to the caller. This package currently implements Delta ADS, not state-of-the-world ADS.

## Build and quick Kubernetes run

Run from the repository root. Go uses this repository's module and generated API; the runner uses client-go for resource operations and port forwarding. The built runner needs a kubeconfig and any authentication plugin required by that config; Python and `kubectl` are not required to execute a run.

```sh
go build -o /tmp/xds-load ./bench/xds/load
go build -o /tmp/xds-run ./bench/xds/run
docker build -f bench/xds/Dockerfile -t xds-load:dev .
kind load docker-image xds-load:dev --name my-test-cluster

/tmp/xds-run \
  --context kind-my-test-cluster \
  --image xds-load:dev --image-pull-policy Never \
  --xds-address agentiod.agentio-system.svc:15012 \
  --server-name agentiod.agentio-system.svc \
  --ca-namespace agentio-system \
  --control-plane agentio-system/agentiod \
  --scenario trafficpolicy --pods 2 --stages 20,100 \
  --rate 10 --rounds 2 --raw-samples \
  --scenario-config '{"rules":50,"ports_per_rule":[1,20]}'
```

Replace the context, service/certificate name, CA ConfigMap location, deployment name and token audience with your installation's values. Load Pods need network access to xDS, and the control plane must trust their projected tokens. The trafficpolicy scenario measures native shared TrafficPolicy updates and observes Sandbox bindings. It requires Sandbox and GlobalTrafficPolicy CRDs and Agentio `AGENTIO_SANDBOX_MODE=true`, `AGENTIO_SANDBOX_RUNTIMES=kruise` and shared TrafficPolicy discovery support. No Kruise Agents installation is required to make the manual Pod/Sandbox bindings. Use a test cluster without a Sandbox lifecycle controller taking over these manual bindings.

For other Kubernetes installations, push the image to an accessible registry and omit `kind load`; `--image-pull-policy Always` is supported. The load application's HTTP API binds to loopback by default; the Kubernetes runner binds Pod port 8088 for readiness probes and accesses it through client-go port forwarding on an automatically allocated loopback port (WebSocket with SPDY fallback). This management API has no authentication and should remain inside the test environment.

To run connection/subscription load without Sandbox resources:

```sh
# Add these options to the connection/CA/image flags above:
--scenario discovery \
--scenario-config '{"types":["type.googleapis.com/istio.workload.Address","type.googleapis.com/istio.security.Authorization"]}' \
--stages 100,1000 --hold-seconds 60 --ack-delay 100ms
```

Discovery readiness requires a response for **every configured type**, including empty responses, followed by successful ACK submission. Only subscribe to types the target supports. TrafficPolicy readiness requires the target native policy and the local Sandbox's Workload binding. Payload/type-specific assertions belong in a scenario, not in `fakeclient`.

For the previous 30,000-connection workload, use `--pods 4 --stages 1000,5000,10000,20000,30000 --rate 200 --rounds 3 --scenario-config '{"rules":50,"ports_per_rule":[1,20]}'`. This runner tests both payload sizes at every stage. Before running, size the control plane and its new-stream admission rate yourself. The earlier test used a 2 CPU limit, an 8 GiB memory limit, `GOMEMLIMIT=6GiB`, `AGENTIO_MAX_REQUESTS_PER_SECOND=500`, and default push concurrency 25. Those settings are test conditions, not universal production sizing recommendations. Default runner admission is a modest 10 new streams/sec total. Each stream has a readiness deadline; failures stop the run and remain in the report.

`--pods` controls distinct Pod/token/Sandbox identities; `--stages` controls total ADS connections distributed across those identities. Increasing one does **not** simulate the other. Stages must strictly increase and be at least the Pod count. The application caps connections per process; the runner sets that cap from the largest stage. This is not a test of business traffic enforcement.

`--setup-wait-seconds 10` optionally waits after creating resources and before opening the first connections. It defaults to zero and is recorded in the run parameters. Use it to separate steady-state push measurements from initial control-plane informer propagation. It is a fixed delay, not a readiness guarantee; connection failures still stop the run without automatic retries.

## Drive the load application directly

Run the binary with `--help` for its connection, authentication, Pod identity and scenario flags. The `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, `NODE_NAME` and `POD_IP` environment variables are defaults for its Agentio identity flags. The generic Go client above does not require these fields; the load application uses them to model dedicated ztunnel identities.

| HTTP endpoint | Purpose |
| --- | --- |
| `POST /scale?n=1000&rate=50` | Ramp this process to 1,000 independent streams at 50 new streams/sec. Only increasing targets; overlapping ramps are rejected. |
| `GET /status` | Connected/ready/dial/error counters, `responses_by_type`, heap/goroutines and active round. |
| `GET /status?samples=1` | Include per-client samples for the current scenario round. |
| `POST /round` | Arm scenario assertions before triggering an update. TrafficPolicy example: `{"id":1,"parameters":{"marker":10001,"action":1,"rule_count":50,"ports":20}}`. Round IDs must increase. |

The HTTP `/round` endpoint carries a common monotonic `id` plus scenario-defined `parameters`. Scenarios with no `PrepareRound` reject it; parameter parsing and matching live in the scenario package. Arm a round only once all clients are ready, then trigger the corresponding update. TrafficPolicy uses a unique first-port marker to distinguish that update from older responses. Avoid adding resource schemas or policy-specific checks to the generic client. SIGINT/SIGTERM closes the HTTP server and all active streams. For a disconnect/reconnect scenario, use the Go client's explicit `Close`/`Open` operations rather than the staged ramp endpoint.

## Outputs and measurements

Results go to a fresh `out/xds/<run-id>` directory, or `--output <new-directory>`:

- `parameters.json`, `results.json`: run identity, parameters, readiness/ramp time, dial counts, failures and latency quantiles. Each round records `round_id`, scenario `parameters` and scenario-specific `checks`; TrafficPolicy checks include `version`, `policy_bytes` and `sandbox_responses_delta`.
- `samples-<connections>-<round-id>.json` with `--raw-samples`: each client's receive/ACK-submit timestamps.
- Pod and optional control-plane deployment snapshots, client port-forward logs.
- `*-usage-<namespace>.json`: raw Pod/container usage from the Kubernetes metrics API if metrics-server is installed; an error object is recorded otherwise. This is periodic observation, not peak CPU/memory.
- Optional raw Prometheus metrics with `--metrics-url http://127.0.0.1:15014/metrics`. Expose that endpoint yourself, e.g. with `kubectl port-forward`. It must be a single matching Agentio instance for ACK-count comparisons to be meaningful.

Latency begins before the Kubernetes policy patch and includes API time, informer/compile/debounce, queueing, transport and client validation. `ack_submit_ms` ends when the client's gRPC `Send` returns, not when the server processes the ACK. `all_clients_observed_ms` uses only the driver's clock and includes management polling overhead. Optional `server_ack_observed_ms` waits for the server's aggregate ACK count to increase by the connection count; unrelated clients can also affect that counter, so it is corroborating evidence, not per-nonce confirmation.

For cross-node clocks the runner estimates each Pod's clock offset from the lowest RTT of three management requests before each update. Reports preserve raw timestamps, offsets, and an approximate half-RTT uncertainty. Asymmetric network paths and later clock drift limit precision; use synchronized clocks and the driver-observed completion time to interpret small differences. P99 is computed separately for each round, not averaged across clients/rounds.

The runner has no automatic control-plane restarts or resource-limit tuning. It also has no retry/reconnect policy that hides dropped streams, no slow-client behavior beyond configurable ACK delay, and no built-in multi-replica routing model. Add a focused scenario using `fakeclient` when testing those behaviors.

## Checks

```sh
go test -race ./bench/xds/...
go vet ./bench/xds/...
go run ./bench/xds/run --help
```

`loadapi/` holds the typed HTTP management messages shared by the load application and runner; the generic ADS client stays independent of that management API. Scenario parameters and check results are opaque to this protocol. `--timeout` and `--hold-seconds` still take numeric seconds.

The client tests exercise real TLS/gRPC connections, arbitrary resource types, initial versions, ACK/NACK, unsubscribe, independent transports, token rotation, context cancellation and readiness timeout accounting. Entry-point and scenario tests cover scenario selection, invalid options, independent instances, per-stream readiness, round markers and policy consistency. Runner tests cover canceled creation cleanup, resource ownership, deadline propagation and incomplete samples. Functional Kubernetes smoke tests exercise both supplied scenarios. Keep benchmark output and binaries outside the tracked source tree; this directory does not contain credentials or historical performance artifacts.
