# SecurityProfile reference

`SecurityProfile` is a namespaced L7 egress policy for selected Pods. `GlobalSecurityProfile` has the same `spec` but is cluster-scoped and can select Pods in every namespace. Both are consumed by Egress Policy Enforcer (EPE); they are distinct from `TrafficPolicy` and `GlobalTrafficPolicy`, which control destination routing rather than request-level actions.

The authoritative API schemas are [`SecurityProfile`](../../manifests/charts/agentio/files/securityprofile-crd.yaml) and [`GlobalSecurityProfile`](../../manifests/charts/agentio/files/globalsecurityprofile-crd.yaml). This page explains the implemented evaluation behavior and links to the schema instead of duplicating generated OpenAPI.

## Scope, selection, and precedence

A `SecurityProfile` selects Pods only in its metadata namespace. A `GlobalSecurityProfile` has no namespace and its selector is considered for every Pod. An empty selector matches every Pod in that scope.

All matching profiles are ordered by lower `spec.priority` first (default `1000`), then earlier creation time, name, and namespace. Global and namespaced profiles are merged into that one order; an exact ordering tie places the global profile first because its namespace is empty.

For each selected request, EPE evaluates every matching rule from the first profile through the last, preserving rule order inside each profile. A terminal action stops the remaining chain. A later rule may still match after a broad earlier rule: matching is not first-rule-wins.

EPE compiles collection-level data when it observes a profile: the label selector, rule matchers and RE2 expressions, audit CEL/templates, and resolved inputs. If that work fails, EPE retains the previous valid version for the resource when one exists. Without a prior valid version, its selected Pods have no protection from that profile. The stale/unenforced metrics and admin state describe only these collection-time failures.

Action configuration is a separate, lazy step. When a request first matches a profile version, EPE projects and caches its action payloads for that version. For token transformations, this is when EPE validates and compiles the signer type, credential-reference normalization, provider parameter CEL/templates, API-key value template, and `when` regex. A projection error affects the matching request; it does not reject the stored profile version, restore an older action payload, or mark the profile stale/unenforced. Projection errors are surfaced as ext_proc processing errors, so the gateway provider's `failureModeAllow` decides whether the request fails closed or bypasses EPE. After projection succeeds, request-time credential lookup, parameter/template evaluation, and signing errors follow the token transformation's `failStrategy`.

## Rule structure and matching

Every rule has a unique `name`, at least one `match` clause, and `actions`. The clauses in `match` are ORed. Within a clause, every populated field is ANDed:

| Field | Behavior |
| --- | --- |
| `domains` | Required. `*` matches any host. `*.example.com` matches subdomains but not `example.com`; exact host matching is case-insensitive. |
| `paths` | ORed. `Prefix` is the default; `Exact` and RE2 `Regex` are supported. The query string is excluded. |
| `methods` | ORed and case-insensitive. The schema restricts the vocabulary to common HTTP methods. |
| `ports` | ORed. EPE uses authority port, HTTP/HTTPS inferred port, then an Envoy destination-port override. Port `0` never matches a non-empty list. |
| `schemes` | ORed and case-insensitive. |
| `headers` | ANDed. Header names are case-insensitive/lowercased; `Exact` is the default, with `Prefix` and RE2 `Regex` available. |
| `queryParams` | ANDed. `Exact` is the default, with `Prefix` and RE2 `Regex`. Only the first percent-decoded value for a repeated key is considered. |

Invalid regexes reject the whole profile version rather than silently making a rule non-matching. The request values and absence rules are detailed in [EPE request context](epe-request-context.md).

## Action order and actions

EPE registers actions in this fixed order within each matched rule:

1. `bypass`
2. `block`
3. `mcpToolPolicy`
4. `tokenTransformation`

`bypass` skips all remaining actions and rules across every matching profile while preserving mutations already made by earlier rules. `block` stops immediately, discards pending mutations, and returns `statusCode` (default 403) with optional `body`.

`mcpToolPolicy` is a non-terminal allow/deny filter for MCP JSON-RPC `tools/call`. `defaultAction` defaults to `deny`; its ordered `rules` match method and optionally tool names. `unsupportedVersionAction` defaults to `deny`, and `denyResponse` defaults to HTTP 403. It buffers complete request bodies and only understands MCP versions currently documented in [Configure MCP access control](../tasks/configure-mcp-access-control.md).

`tokenTransformation` is non-terminal. It has these fields:

| Field | Behavior |
| --- | --- |
| `type` | `ApiKey` (default) injects a rendered credential into `targetHeader` (default `Authorization`); `AliyunSTS` re-signs a detected ACS3/V3, V1-ROA, OSS V4, or V1-RPC request using an STS triplet. |
| `credentialRef` | Required typed union: exactly one `secret` or `credentialProvider`. Deprecated flat `kind`/`name`/`namespace` values are normalized for compatibility but must not be mixed with the typed form. |
| `credentialRef.secret` | `name` is required; namespace falls back from reference to profile to source Pod. `ApiKey` reads `apiKey`; `AliyunSTS` reads `accessKeyId`, `accessKeySecret`, `securityToken`. |
| `credentialRef.credentialProvider` | `name` is required. `parameters` supplies metadata values from exactly one of `value`, `template`, or `cel`. Its namespace field is currently ignored. |
| `apiKey` | Required for `ApiKey`, ignored for `AliyunSTS`. `valueTemplate` is required. Optional `when.header` and RE2 `when.pattern` gate the transform on an existing header. |
| `disabled` | Defaults to `false`; when true, leaves the configuration stored but does not mount the action. |
| `failStrategy` | `Block` (default) denies with generic 403; `Allow` and `Ignore` pass the failed transformation through unmodified. |

An unavailable signer type or malformed credential reference fails during lazy action projection and produces an ext_proc processing error governed by the provider's `failureModeAllow`, as described above. After projection succeeds, an unavailable credential, bad provider response, invalid header value, or signing error uses the token transformation's `failStrategy`. Provider details, TLS, and cache semantics are in [Credential provider](credential-provider.md).

`AliyunSTS` detects ACS3/V3, V1-ROA, and OSS V4 from the trimmed `Authorization` header. Their required prefixes are `ACS3-HMAC-SHA256`, `acs` (also requiring a `:`), and `OSS4-HMAC-SHA256`, respectively, each followed by a space. When none matches, V1-RPC is detected from a parseable raw query containing non-empty `Signature` and `AccessKeyId` parameters and exactly `SignatureMethod=HMAC-SHA1`. A request that meets none of these requirements is unsupported; detection fails and the action follows its configured `failStrategy` (`Block` by default, or unmodified forwarding for `Allow`/`Ignore`).

## Audit configuration

`spec.audit` defines profile defaults. A non-empty `rules[].actions.audit` list replaces those defaults for that rule; an empty rule list inherits the profile list. Every audit action has a unique `name`, a required webhook `url`, optional boolean CEL `when`, and a webhook request:

- Request method is `POST` by default and may be `POST`, `PUT`, or `PATCH`.
- Timeout defaults to `2s` and must be 500 ms through 30 s.
- Headers and text/JSON body leaves are Go templates. JSON bodies preserve non-string values and render string leaves.
- Audit is asynchronous and fires after stream resolution. Template/evaluation failures drop that event; audit never changes the request verdict or upstream response.

Audit CEL sees `result` and `response.status` in addition to the request context. It may send selected request, input, and match information to the webhook, so treat its endpoint as a data-disclosure boundary.

## Inputs and credential references

`spec.inputs` provides named configuration values to CEL and Go templates. Each entry contains exactly one `inline` string map or `configMap` source. A namespaced profile defaults a ConfigMap namespace to its own namespace; a global profile requires it. Inputs are resolved profile-wide, not per-rule and not per-request credentials.

Use `credentialRef` for credentials and `inputs` for non-secret configuration such as tenant or routing labels. EPE does not redact input values in templates, provider metadata, or audit requests.

## Defaults and validation

The CRD validates required fields, enum values, header-name syntax, lengths, ports, and audit timeout bounds. At collection time, EPE additionally validates selector parsing, rule-match regex compilation, one source per input, required input availability, and audit CEL/template compilation and types. Token action validation is lazy as described under [Scope, selection, and precedence](#scope-selection-and-precedence); it is not part of the last-known-good profile decision.

Notable defaults are priority `1000`, `block.statusCode` `403`, MCP `defaultAction`/`unsupportedVersionAction` `deny`, token type `ApiKey`, token target header `Authorization`, token failure strategy `Block`, and token `disabled` `false`.

## GlobalSecurityProfile differences

`GlobalSecurityProfile` is cluster-scoped, participates in selection for every source namespace, and has an empty profile namespace in templates/CEL/audit. Because it has no own namespace, any ConfigMap input must specify one, and a Secret credential reference without a namespace falls back to each selected Pod's namespace. The actions, matching, priority, audit, and validation rules are otherwise the same as `SecurityProfile`.

## See also

- [EPE request context](epe-request-context.md)
- [Credential provider contract](credential-provider.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [`SecurityProfile` CRD schema](../../manifests/charts/agentio/files/securityprofile-crd.yaml)
- [`GlobalSecurityProfile` CRD schema](../../manifests/charts/agentio/files/globalsecurityprofile-crd.yaml)
