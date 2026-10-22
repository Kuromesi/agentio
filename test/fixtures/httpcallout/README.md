# HTTPCallout test server

The standalone server implements EPE's HTTPCallout protocol using the production `Invocation` / `Decision` types. It validates invocations, limits request JSON to 8 MiB, and never logs request bodies or credentials. It is a test application, not an authorization service. Bind to loopback by default; use `-listen :18080` only when a remote test proxy needs to reach it.

From the repository root:

```sh
go run ./test/fixtures/httpcallout/server -listen 127.0.0.1:18080
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

GET `/healthz` checks readiness. GET `/stats` returns validated call count, currently active calls, and calls canceled during delay. Counters do not retain request data. Successful decision responses have protocol version `0.1`.

## Tests and reuse

Run `go test -race ./test/fixtures/httpcallout/...` from the repository root. The existing ext-proc fixture image also serves this handler with `-http-callout-port=8080`; the product E2E suite deploys that mode, so it needs no additional image input.

`TestHTTPCalloutFixture` in `test/e2e/suites/epe` verifies Kubernetes deployment, Service reachability, both invocation phases, mutations, local responses, invalid input, failure responses and counters. With the product E2E image inputs configured, run `go run ./cmd/product-e2e run --suites epe --tests '^TestHTTPCalloutFixture$'` from `test/e2e`.

SecurityProfile HTTPCallout action integration is currently deferred. This cluster test calls the fixture directly; it does not claim to exercise EPE policy distribution. The [Envoy integration and performance tests](../../../bench/epe/callout/README.md) cover EPE's real callout client, engine, buffering, fail-open/closed behavior and recovery with a static policy resolver.
