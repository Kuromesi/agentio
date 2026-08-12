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

The binary defaults `--enable-debug=true`. Starting it with `--enable-debug=false` leaves the index available but does not register debug paths; requests to `/debug/profiles` then return 404.

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
| Unknown path, or debug path while disabled | `404` |

The API is read-only, but it exposes profile selectors, ordering, and, in full mode, complete policy specifications. Do not set `--admin-addr=:15000` or any other non-loopback address without restrictive NetworkPolicies, service exposure controls, and authentication in an enclosing trusted boundary. The server itself provides no authentication or authorization.

## See also

- [EPE configuration](epe-configuration.md)
- [EPE observability](epe-observability.md)
- [Troubleshoot EPE](../tasks/troubleshoot-epe.md)
