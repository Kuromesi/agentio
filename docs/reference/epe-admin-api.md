# EPE admin API

The Egress Policy Enforcer (EPE) always starts an HTTP admin server. Its default bind address is `127.0.0.1:15000`, which makes it available only inside the EPE Pod unless an operator changes `--admin-addr`. The Kubernetes Service does not expose this port. Use port-forwarding for inspection:

```console
$ EPE_POD=$(kubectl get pod --namespace agentio-system \
    --selector app.kubernetes.io/name=agentio-epe \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$EPE_POD"
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 15000:15000
```

## Index endpoint

`GET /` is always available and returns plain text. It lists available debug endpoints and says whether they are enabled. Only the exact root path is an index: unknown paths return `404 Not Found`.

```console
$ curl --fail --silent http://127.0.0.1:15000/
```

The binary defaults `--enable-debug=true`. Starting it with `--enable-debug=false` leaves the index available but does not register debug paths; requests to `/debug/profiles` and `/debug/logging` then return 404.

## Runtime log level

`GET /debug/logging` reports the current EPE process log level. `PUT /debug/logging` changes it immediately for existing loggers, without restarting the Pod. Both return `200 OK` with a JSON `level` string and `Cache-Control: no-store`.

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/logging
{"level":"2"}

$ curl --fail --silent --request PUT \
    --header 'Content-Type: application/json' \
    --data '{"level":"4"}' \
    http://127.0.0.1:15000/debug/logging
{"level":"4"}
```

The level uses the same convention as `--zap-log-level`: a Zap level name or a numeric string for logr verbosity. EPE's request-path debug logs use verbosity **4**; the Zap name `debug` enables only verbosity **1**.

| `level` value | Effect |
| --- | --- |
| `"0"` or `"info"` | INFO and higher; suppresses all `V(1)` and more verbose records. |
| `"1"` or `"debug"` | Enables `V(1)` and direct slog debug records. |
| `"2"` | EPE's default verbosity, equivalent to `-v=2`. |
| `"3"` | Enables EPE verbose records. |
| `"4"` | Enables EPE debug records, including token-transformation and ext_proc diagnostics. |
| `"5"` | Enables EPE trace records. |
| `"warn"`, `"error"`, `"dpanic"`, `"panic"`, `"fatal"` | Sets the corresponding Zap minimum level. |

Numeric strings from `"0"` through `"127"` are accepted. Responses normalize `"0"` to `"info"` and `"1"` to `"debug"`; other numeric verbosity levels remain numeric strings. Send exactly one JSON object containing a non-empty `level` string. Invalid values, unknown fields, trailing JSON, and bodies larger than 4 KiB return `400` without changing the level. Other HTTP methods return `405` with `Allow: GET, PUT`.

To restore the default EPE verbosity, PUT `{"level":"2"}`. A runtime change applies only to the EPE process reached by this request; configure each replica separately if necessary. Changes are not persisted: a restart restores `-v` or the overriding `--zap-log-level`. Encoding, stacktrace thresholds, and startup sampling configuration stay unchanged.

The endpoint controls EPE's shared Zap core, including existing controller-runtime loggers and the slog/klog bridge. Shared Agentio packages such as `pkg/krt` retain their separate INFO scope gate, so increasing EPE verbosity does not enable those packages' DEBUG records. This endpoint does not change agentiod logging.

## Profile inspection endpoint

When debug is enabled, `GET` and `POST /debug/profiles` list compiled `SecurityProfile` and `GlobalSecurityProfile` identities from EPE's in-memory store. Every JSON response has `Content-Type: application/json; charset=utf-8` and `Cache-Control: no-store`.

### List mode

List mode returns every loaded profile, optionally filtering exact namespaced profiles by `namespace`. A namespace filter excludes global profiles. Results are sorted in the same order EPE evaluates them: priority, creation timestamp, name, then namespace.

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/profiles
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo'
$ curl --fail --silent --request POST \
    --header 'Content-Type: application/json' \
    --data '{"namespace":"agent-demo"}' \
    http://127.0.0.1:15000/debug/profiles
```

### Match mode

Supply pod labels and a namespace to see the profiles EPE would match for a Pod. A GET uses comma-separated `key=value` pairs in `pod_labels`; a POST uses an object. Match results are returned in evaluation order. A namespace is required whenever labels are supplied.

```console
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo&pod_labels=app=agent-demo,team=payments'

$ curl --fail --silent --request POST \
    --header 'Content-Type: application/json' \
    --data '{"namespace":"agent-demo","pod_labels":{"app":"agent-demo","team":"payments"}}' \
    http://127.0.0.1:15000/debug/profiles
```

The endpoint matches profile selectors only. It does not run HTTP rule matching, fetch credentials, evaluate request bodies, or predict a final request decision.

### Response shape and full mode

The default response returns identity and ordering fields only:

```json
{
  "count": 1,
  "profiles": [
    {
      "kind": "SecurityProfile",
      "namespace": "agent-demo",
      "name": "audit-blocked-admin",
      "priority": 1000
    }
  ]
}
```

`kind` is `SecurityProfile` or `GlobalSecurityProfile`; a global profile has an empty `namespace`. Add `full=true` to a GET or `"full": true` to a POST to fetch each current complete profile spec from the Kubernetes API and include `creationTimestamp` and `spec`:

```console
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo&full=true'
```

If EPE cannot fetch one profile's live content, the response remains `200 OK` and that profile carries an `error` field. The identity fields remain valid. Full mode can disclose policy templates, inline inputs, and other sensitive configuration; use it only from trusted operator workstations.

## Errors and limits

| Request | Status and response |
| --- | --- |
| `PUT`, `DELETE`, or another unsupported method on `/debug/profiles` | `405` JSON `{"error":"method not allowed; use GET or POST"}` and `Allow: GET, POST` |
| Labels supplied without `namespace` | `400` JSON error |
| Malformed POST JSON | `400` JSON error |
| POST body larger than 1 MiB | `400` JSON error from the request decoder |
| Invalid logging configuration or PUT body larger than 4 KiB on `/debug/logging` | `400` JSON error; current level is unchanged |
| Unsupported method on `/debug/logging` | `405` JSON error and `Allow: GET, PUT` |
| Unknown path, or debug path while disabled | `404` |

The API exposes profile selectors, ordering, and, in full mode, complete policy specifications. It also permits runtime log-level changes, which can increase log volume or suppress diagnostics. Do not set `--admin-addr=:15000` or any other non-loopback address without restrictive NetworkPolicies, service exposure controls, and authentication in an enclosing trusted boundary. The server itself provides no authentication or authorization.

## See also

- [EPE configuration](epe-configuration.md)
- [EPE observability](epe-observability.md)
