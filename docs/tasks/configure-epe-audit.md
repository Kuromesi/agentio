# Configure EPE audit events

The Egress Policy Enforcer (EPE) can emit an asynchronous audit webhook after a matched `SecurityProfile` rule reaches its final outcome. Audit delivery does not alter the request result: a failed, slow, or dropped audit event never changes an allow, block, mutation, or bypass decision.

## Before you begin

This task assumes that EPE is enabled, the selected workload reaches an EPE enabled egress gateway, and an audit receiver is reachable from the `agentio-epe` Pod. Complete [Get started with EPE](../getting-started/epe.md) and keep the workload namespace and Pod available:

```console
$ : "${AGENTIO_DEMO_NAMESPACE:?Set the namespace containing the selected workload}"
$ : "${AGENTIO_WORKLOAD_POD:?Set the selected workload Pod name}"
$ : "${AGENTIO_WORKLOAD_CONTAINER:?Set the workload container name}"
```

The example below matches `https://api.example.com`. Configure the selected gateway to terminate TLS for `api.example.com`, ensure the chart renders `ENABLE_ON_DEMAND_CERTS=true`, and make the workload trust the signing CA before testing it. Without those settings, HTTPS remains on the gateway's TCP path and bypasses EPE's HTTP filter chain. Follow [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

Audit is part of `SecurityProfile` and `GlobalSecurityProfile`; it is not part of `TrafficPolicy` or `GlobalTrafficPolicy`. The latter resources select and route Layer 4 traffic, while an EPE audit records the outcome of Layer 7 `SecurityProfile` rule evaluation.

## Add an audit action

An audit list at `spec.audit` is inherited by matched rules. A non-empty `rules[].actions.audit` list replaces that inherited list for that rule. Each entry has a name, a webhook, and an optional CEL `when` condition. An omitted `when` always fires.

Apply the following complete namespaced profile. Replace the receiver URL and the selector before using it in a shared cluster. Its rule blocks `GET https://api.example.com/admin`, and its audit action sends an event only when the final result is `blocked`.

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<'EOF'
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: audit-blocked-admin
spec:
  selector:
    matchLabels:
      app: agent-demo
  audit:
  - name: blocked-request
    when: result == "blocked"
    webhook:
      url: "https://audit-receiver.example.com/v1/events"
      timeout: 2s
      request:
        method: POST
        headers:
        - name: X-Agentio-Audit-Type
          value: "blocked-request"
        body:
          json:
            result: "{{ .Result }}"
            profile: "{{ .Profile.Name }}"
            namespace: "{{ .Profile.Namespace }}"
            rule: "{{ .Rule.Name }}"
            host: "{{ .Request.Host }}"
            path: "{{ .Request.Path }}"
            method: "{{ .Request.Method }}"
            status: "{{ .Response.Status }}"
  rules:
  - name: deny-admin
    match:
    - domains:
      - api.example.com
      methods:
      - GET
      paths:
      - type: Exact
        value: /admin
    actions:
      block:
        statusCode: 403
        body: request blocked by policy
EOF
```

The webhook URL must render to an absolute `http` or `https` URL. Its timeout defaults to `2s` and is limited by the CRD to `500ms` through `30s`. The request method defaults to `POST`; the supported explicit methods are `POST`, `PUT`, and `PATCH`. An absent request body is an empty body. A JSON body keeps non-string values and renders every string leaf as a Go template; a `text` body renders as `text/plain` instead.

## Use CEL and templates safely

`when` must compile to a boolean. A compile error prevents that profile version from loading. A runtime evaluation error drops only that audit event and increments `epe_audit_eval_dropped_total{reason="when_eval"}`.

CEL exposes these variables:

| Variable | Fields |
| --- | --- |
| `result` | `passthrough`, `mutated`, `blocked`, `bypassed`, or `error` |
| `request` | `host`, `port`, `path`, `method`, `scheme`, lowercase `headers`, and first-value `queryParams` |
| `pod` | `name`, `namespace`, `ip`, and `labels` |
| `profile` | `name` and `namespace` |
| `rule` | Matched rule `name` |
| `inputs` | Profile-scoped inputs |
| `response` | `status`; zero when EPE did not observe a response |

For example, `result == "blocked" && request.path.startsWith("/admin")` fires only for denied administrative paths. Go templates use the same data via accessors such as `{{ .Request.Host }}`, `{{ .Request.Header "X-Request-Id" }}`, `{{ .Request.QueryParam "page" }}`, `{{ .Pod.Label "app" }}`, and `{{ .MatchedCriteria.Host }}`. `MatchedCriteria` contains the dimensions of the rule match that fired: host, method, path, port, matched headers, and matched query parameters.

EPE deliberately does not expose the sandbox token, request body, credentials, or secrets in this context. Request headers, query values, Pod labels, and profile inputs can still be sensitive. Do not render them into a URL, header, or webhook body unless the receiver is authorized to retain them. Prefer a dedicated HTTPS receiver, minimal fields, and receiver-side access controls.

The response status is normally zero because the chart wires response headers as `SKIP`. There are two ways to deliver response headers to EPE: set the binary-only `--observe-responses=true`, which emits a per-request mode override to `SEND` even over the static chart setting, or configure `sandboxExtProc.response.headerMode: SEND` statically. Either choice adds one ext_proc message for every forwarded request and can add latency; neither makes the response body available to audit templates.

## Understand delivery and backpressure

EPE writes a separate structured access log for every successfully handled request-header stream. The log includes `requestID`, `pod`, HTTP method, host, path, matched unit count, final outcome, actions, skipped filters, and an error when present. It uses one worker and a non-blocking queue of 4,096 entries by default; a full queue drops the log entry and increments `epe_audit_log_dropped_total`.

Webhook events are rendered after the final rule outcome, then placed on a non-blocking bounded queue. The defaults are 8,192 entries and 96 workers; the `--audit-webhook-buffer-size` and `--audit-webhook-workers` flags change them. A full queue drops the event rather than delaying the request. On EPE shutdown, accepted work gets up to five seconds to drain; remaining work and late events are dropped. Track `epe_audit_webhook_dropped_total` for `buffer_full`, `draining`, `stopped`, or `shutdown_timeout`.

EPE does not retry audit webhooks. It records a `success`, `http_error`, `transport_error`, or `timeout` in `epe_audit_webhook_dispatched_total`; HTTP responses with status 400 or higher are `http_error`. Rendering failures, non-HTTP(S) URLs, and bodies larger than 64 KiB are dropped before dispatch and reported through `epe_audit_webhook_dropped_total`. The default binary setting skips TLS certificate verification for audit webhooks; set `--audit-webhook-insecure-skip-verify=false` for a production HTTPS receiver with a valid certificate chain.

The Helm chart does not expose the audit queue, worker, TLS-verification, or response-observation flags. They require an explicit container argument override or a derived deployment/image; `epe.env` cannot set command-line flags. See [EPE configuration](../reference/epe-configuration.md).

## Verify audit output

First, confirm that the profile was accepted and that EPE has loaded it. The admin endpoint is loopback-only in the Pod, so port-forward it rather than changing its bind address:

```console
$ EPE_POD=$(kubectl get pod --namespace agentio-system \
    --selector app.kubernetes.io/name=agentio-epe \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$EPE_POD"
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 15000:15000
```

In another terminal, inspect the compiled profile identity:

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/profiles?namespace="$AGENTIO_DEMO_NAMESPACE"
```

Trigger the matching request through the workload and expect a non-zero `curl` exit caused by the policy's 403 response:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error https://api.example.com/admin
```

In one terminal, port-forward the metrics endpoint:

```console
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 9090:9090
```

While the port-forward is running, use another terminal to check that the receiver result counter and the access log stream show the outcome. A successful receiver increments the `success` series; an unavailable receiver increments a failure series but does not alter the 403.

```console
$ curl --fail --silent http://127.0.0.1:9090/metrics \
  | grep '^epe_audit_webhook_dispatched_total'

$ kubectl logs --namespace agentio-system "$EPE_POD" \
  | grep 'egress request handled'
```

## Clean up

```console
$ kubectl delete securityprofile audit-blocked-admin \
    --namespace "$AGENTIO_DEMO_NAMESPACE"
```

## See also

- [EPE observability](../reference/epe-observability.md)
- [EPE configuration](../reference/epe-configuration.md)
- [EPE admin API](../reference/epe-admin-api.md)
- [Troubleshoot EPE](troubleshoot-epe.md)
