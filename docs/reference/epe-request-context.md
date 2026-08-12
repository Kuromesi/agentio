# EPE request context

This reference defines the context that Egress Policy Enforcer (EPE) exposes while evaluating a `SecurityProfile` or `GlobalSecurityProfile`. It lists only the values implemented by `extensions/epe/`; fields not listed here are not policy APIs.

EPE receives request data through Envoy external processing. Header names are normalized to lowercase. EPE buffers a request body only when a matched action requires it; body bytes and the sandbox bearer token are deliberately not exposed to CEL, Go templates, profile inputs, or audit payloads.

## Request attributes

EPE builds the request tuple during request headers. `:authority` takes precedence over `host`; its explicit port is used, otherwise `http` defaults to 80 and `https` to 443. Envoy's `destination.port`, when present and between 1 and 65535, overrides that inferred port.

| Attribute | Type | Source and absence behavior |
| --- | --- | --- |
| `host` | string | Authority/Host name without brackets or port. Empty if neither is sent. |
| `port` | int | Explicit authority port, inferred HTTP/HTTPS port, or Envoy `destination.port`. `0` if unavailable or invalid. |
| `path` | string | Portion of `:path` before `?`; empty when absent. |
| `method` | string | `:method`; empty when absent. |
| `scheme` | string | `:scheme`; empty when absent. |
| `headers` | map<string, string> | Request headers keyed in lowercase. In CEL, indexing an absent key raises a `no such key` evaluation error; duplicate values are collapsed to the last value supplied by Envoy. |
| `queryParams` | map<string, string> | First parsed value of each query parameter. It is empty when there is no query. Invalid query syntax can be partially parsed; semicolon-separated pairs and invalid escapes are not a byte-for-byte policy surface. |

Policy matching sees the same host, port, path, method, scheme, headers, and parsed query fields. Path matching excludes the query string. Query matching uses the first percent-decoded value for a key.

## Source peer and stream information

Envoy filter-state attributes identify the caller:

| EPE stream field | Envoy attribute | Type | Absence behavior |
| --- | --- | --- | --- |
| Pod namespace | `filter_state['downstream_peer'].namespace` | string | Empty makes the peer invalid. |
| Pod name | `filter_state['downstream_peer'].name` | string | Empty makes the peer invalid. |
| Pod IP | `source.address` | string | EPE removes a valid port and surrounding IPv6 brackets. It is empty when absent; otherwise malformed input may be preserved after this syntactic stripping. |
| Pod labels | `filter_state['sandbox.labels']` | map<string, string> | Parsed from base64 `k=v,k2=v2`; empty on absent or invalid input. |
| Sandbox token | `filter_state['sandbox.token']` | internal object | Base64 JSON or raw JSON with `requestId`, `accessToken`, and `sandboxClientId`; nil when absent or malformed. Not expression-visible. |
| Request ID | `x-request-id` | string | Empty when absent. Used for log correlation, not expression evaluation. |

Both Pod namespace and name are required. Without them EPE cannot select a profile and passes the request through. The token is consumed only by provider-backed credential transformations; its bearer `accessToken` is never exposed in `request`, `pod`, `inputs`, templates, CEL, or audit context.

The filter stream also records matched profile/rule actions, filter outcomes, final disposition (`passthrough`, `mutated`, `blocked`, `bypassed`, or `error`), any resolved error text, and bytes forwarded before a verdict. These are internal/audit observations, not general CEL variables.

## Phase availability

| Phase | Available data | Mutability and limits |
| --- | --- | --- |
| Request headers | Request tuple, peer identity, profile/rule, and resolved inputs. | Matching and header transformations occur here. `block` and `bypass` are header-only. |
| Request body | The same request context plus a complete buffered body only for actions that request it. | Current body consumers are MCP ACL and body-dependent signing. The body is not exposed to CEL/templates. Buffered mode prevents bytes from reaching upstream before the verdict. |
| Response headers | Upstream response status and lowercased response headers are recorded on the stream. | The current response phase is observation-only: filters cannot mutate response headers. Only status reaches audit CEL/templates. |
| Stream end | Final disposition and response status, if response headers arrived. | Audit actions are evaluated asynchronously; they cannot modify the already-resolved request or upstream response. |

Request and response bodies are not expression-visible. EPE's response-body and trailer handlers currently pass through. A blocked request may have no upstream response, in which case audit `response.status` is `0`.

## Shared inputs

`SecurityProfile.spec.inputs` creates profile-scoped values under `inputs`. An input sets exactly one source:

- `inline` is a `map<string, string>` stored in the profile.
- `configMap` reads ConfigMap `data` into a `map<string, string>`. A namespaced `SecurityProfile` defaults the ConfigMap namespace to its own namespace. A `GlobalSecurityProfile` must name a ConfigMap namespace explicitly.

Inputs are configuration, not credentials. EPE resolves them when the profile is compiled; a missing ConfigMap or invalid input rejects the candidate profile. The store retains the last known good version for an invalid update when one exists. Do not put secrets, sandbox identities, or generated credential material in inputs.

## CEL variables and functions

EPE uses one CEL environment for rule/audit conditions and provider parameter values. `when` expressions must return `bool`; an empty `when` is true. Provider `parameters[].cel` may return any JSON-compatible value other than null.

| Variable | CEL type | Values |
| --- | --- | --- |
| `request` | `map<string, dyn>` | `host`, `port` (int), `path`, `method`, `scheme`, `headers`, `queryParams`. |
| `pod` | `map<string, dyn>` | `name`, `namespace`, `ip`, `labels`. |
| `profile` | `map<string, string>` | `name`, `namespace` (empty for a global profile). |
| `rule` | `map<string, string>` | `name`. |
| `inputs` | `map<string, dyn>` | Named inline/ConfigMap input maps; it may be nil when no inputs are configured. |
| `result` | string | Audit only: final disposition. It is not available to request-time provider parameters. |
| `response` | `map<string, dyn>` | Audit only: `status` (int; `0` if no response observed). |

The CEL environment includes the standard CEL binding, string, set, and list extensions. CEL receives ordinary maps, so direct indexing of a missing header, label, query parameter, or input key raises a `no such key` evaluation error; it does not produce an empty string. Guard membership before indexing, for example, `"content-type" in request.headers && request.headers["content-type"].startsWith("application/json")`. An audit CEL runtime error drops that audit event, while a provider-parameter CEL runtime error follows the matched token transformation's `failStrategy`.

## Template values and functions

Go templates use `missingkey=zero` and the helper functions `default fallback value` and `json value`. Unlike CEL map indexing, the `.Request.Header` and `.Request.QueryParam` accessors return `""` when the requested key is absent. Request credentials are intentionally unavailable.

| Template root | Values |
| --- | --- |
| Token transformation `apiKey.valueTemplate` | `.Token`, `.Pod`, `.Inputs` only. `.Pod` has `Name`, `Namespace`, `IP`, `Labels`, and `Label key`; `.Inputs` is the profile input map. |
| Credential-provider parameter `template` | `.Request`, `.Pod`, `.Profile`, `.Rule`, `.Inputs`. `.Request` has `Host`, `Port`, `Path`, `Scheme`, `Method`, `Query`, `Header name`, and `QueryParam name`. |
| Audit webhook URL, headers, and body | The shared roots above plus `.Result`, `.Response.Status`, and `.MatchedCriteria`/`.Matched`. Matched fields are populated only when the corresponding rule match constrained them. |

Use lower-risk data in audit and provider templates. Rendered values can be transmitted to external providers/webhooks, and the `json` helper serializes its argument rather than redacting it.

## See also

- [SecurityProfile reference](security-profile.md)
- [Credential provider contract](credential-provider.md)
- [Configure MCP access control](../tasks/configure-mcp-access-control.md)
- [Transform outbound credentials](../tasks/transform-outbound-credentials.md)
