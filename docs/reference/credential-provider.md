# Credential Provider Contract

EPE's `tokenTransformation` action injects or re-signs credentials on egress requests so that long-lived secrets never enter the sandbox. The credentials themselves come from a **credential provider**: an HTTP service that EPE calls at request time to exchange a sandbox's identity for a short-lived API key or STS triplet.

The credential provider is an **extension point, not a fixed backend**. Any service that implements the contract below works; integrations that target a specific cloud vendor (for example an Alibaba Cloud-backed provider) are implementations of this same contract. EPE ships the client side only (`extensions/epe/pkg/credential`).

Configure a policy consumer with [Transform outbound credentials](../tasks/transform-outbound-credentials.md). For the `SecurityProfile` action fields, credential-reference forms, and provider parameter expressions, see the [SecurityProfile reference](security-profile.md).

## Request flow

```text
sandbox ──> egress gateway ──ext_proc──> EPE ──HTTPS/mTLS──> credential provider
                                          │
                                          └─ injects apiKey / signs with STS
```

1. The data plane attaches the caller's identity as `filter_state['sandbox.token']`: base64-encoded (or raw) JSON of

   ```json
   { "requestId": "...", "accessToken": "...", "sandboxClientId": "..." }
   ```

2. When a matched rule carries `tokenTransformation` with a `credentialRef.credentialProvider`, EPE calls the provider using `accessToken` as the bearer credential and `sandboxClientId` as the resource being acted for.

3. The provider authenticates the caller (mTLS client certificate and the bearer token), authorizes the `(resource, provider name)` pair, and returns the credential.

## Wire contract

One endpoint, configured by the `IDENTITY_PROVIDER_URL` environment variable (chart value `epe.credentialProvider.url`). The environment variable's name predates the credential-provider naming and is retained for compatibility. EPE sends:

```text
POST <IDENTITY_PROVIDER_URL>
Authorization: Bearer <accessToken>
X-Api-Action-Name: GetResourceCredential
Content-Type: application/json
```

Request body:

```json
{
  "resourceId": "<sandboxClientId>",
  "credentialProviderName": "<SecurityProfile credentialRef.credentialProvider.name>",
  "credentialType": "apiKey" | "stsToken",
  "extraMetadata": { "<parameter>": <any JSON value> }
}
```

- `credentialProviderName` selects a provider configuration on the server side; it is the `name` from the SecurityProfile's `credentialRef.credentialProvider`.
- `extraMetadata` carries the rule's `credentialProvider.parameters` after CEL evaluation (values may be strings, lists, or any JSON-compatible value). Omitted when empty.

Success response — `200 OK` with a JSON body. Exactly one of the credential fields is expected, matching the requested `credentialType`:

```json
{ "requestId": "...", "apiKey": "sk-...", "cacheExpiresInSeconds": 600 }
```

`cacheExpiresInSeconds` is optional; see [caching semantics](#caching-semantics).

```json
{
  "requestId": "...",
  "stsToken": {
    "accessKeyId": "...",
    "accessKeySecret": "...",
    "securityToken": "...",
    "expiration": "2026-01-01T00:00:00Z"
  }
}
```

- `stsToken.expiration` is RFC 3339 and optional; when present it bounds the cache lifetime (see below).
- An empty `apiKey`, or an `stsToken` missing any of the three key fields, is treated as a failure by EPE.

Failure response — any non-200 status. The body is logged and surfaced in the error. EPE does not retry; the failure resolves through the matched rule's `failStrategy` (block the request or pass it through unmodified).

## Transport security

`CREDENTIAL_PROVIDER_MTLS_SOURCE` names the single source of EPE's mTLS material. There is deliberately no fallback between sources: a Secret missing its CA does not borrow the CA from disk.

| Source | Where the material comes from |
| --- | --- |
| `files` (default) | `CREDENTIAL_PROVIDER_CLIENT_CERT_PATH` / `CREDENTIAL_PROVIDER_CLIENT_KEY_PATH` / `CREDENTIAL_PROVIDER_CA_CERT_PATH` (defaults `/etc/epe/credential-provider/{client.crt,client.key,ca.crt}`, where the chart mounts the optional `<name>-mtls-client-cert` Secret). |
| `secret` | The Secret named by `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `CREDENTIAL_PROVIDER_SECRET_NAME`, data keys `ca.crt`, `client.crt`, `client.key`. Both variables are required. |
| `none` | No material at all. |

Within the chosen source the client identity and the trust anchors are independent: a source may supply anchors without an identity, or an identity without anchors. Material that is absent or unusable means EPE presents no client certificate and verifies the provider against the system trust store; it is never a startup failure. Only a misconfigured source is — an unrecognized `CREDENTIAL_PROVIDER_MTLS_SOURCE` value, or `secret` without both a namespace and a name.

The chosen source is watched for the lifetime of the process, so material that appears or rotates after startup takes effect without a restart. A Secret that does not exist yet, or that the ServiceAccount may not read, degrades to no client identity while EPE keeps waiting for it. TLS 1.2 is the minimum in every case.

`CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY=true` is an explicit exception for trusted test environments: it disables provider server-certificate verification while retaining any configured client certificate. It exposes the bearer token and returned credentials to an on-path attacker and must not be used in production.

Providers should require the client certificate and treat the bearer `accessToken` as the per-sandbox authorization, not as the only authentication factor.

## Caching semantics

Providers must tolerate credential reuse within a bounded window; EPE caches per `(providerName + hash(extraMetadata), resourceId)`:

| Credential | Lifetime | Size bound |
| --- | --- | --- |
| `apiKey` | `cacheExpiresInSeconds` when the response carries it, else `TOKEN_CACHE_TTL` (chart default `15m`) | `TOKEN_CACHE_MAX_SIZE` |
| `stsToken` | until `stsToken.expiration` (uncacheable without it) | `STS_CACHE_MAX_SIZE` |

`cacheExpiresInSeconds` is an optional field on an `apiKey` response naming how many seconds that key may be cached. It takes precedence over `TOKEN_CACHE_TTL` and is applied verbatim — no safety margin is subtracted, unlike `stsToken.expiration`. Absent, `null`, zero, and negative all mean "no opinion" and `TOKEN_CACHE_TTL` applies.

It must be a JSON **integer** (`600`), not a string (`"600"`) and not fractional (`600.5`). EPE decodes it as part of the credential response, so a non-integer value fails that decode and the `apiKey` becomes unreachable — the request then follows `failStrategy` instead of merely losing the caching hint. Providers must not quote this field.

Practical consequences:

- Key rotation on the provider side becomes visible to EPE only after the cache entry expires. Returning `cacheExpiresInSeconds` is the direct way to control this per credential; `TOKEN_CACHE_TTL` is the deployment-wide fallback for providers that do not.
- A non-positive `TOKEN_CACHE_TTL` is honoured rather than corrected: it disables the fallback lifetime, so responses without `cacheExpiresInSeconds` are not cached at all.
- Returning `expiration` on STS responses is strongly recommended — it is the only way the provider controls STS reuse.

## Environment variable reference

| Variable | Meaning |
| --- | --- |
| `IDENTITY_PROVIDER_URL` | Provider endpoint; unset means provider-backed rules fail through `failStrategy` |
| `CREDENTIAL_PROVIDER_MTLS_SOURCE` | The single source of mTLS material: `files` (default), `secret`, or `none` |
| `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `_NAME` | Secret holding mTLS material; both required by the `secret` source |
| `CREDENTIAL_PROVIDER_CLIENT_CERT_PATH` / `_KEY_PATH` / `_CA_CERT_PATH` | Paths read by the `files` source |
| `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE` | API-key cache tuning; `TOKEN_CACHE_TTL` is the fallback lifetime for responses without `cacheExpiresInSeconds` |
| `STS_CACHE_MAX_SIZE` | STS cache tuning |

## Implementing a provider

A conforming provider must:

1. Serve `POST` on a single HTTPS endpoint and read `X-Api-Action-Name: GetResourceCredential`.
2. Authenticate the mTLS client certificate and the `Authorization: Bearer` token; authorize the `(resourceId, credentialProviderName)` pair.
3. Return `200` with `apiKey` or a complete `stsToken` per the requested `credentialType`; return a non-200 status with a diagnostic body otherwise.
4. Issue short-lived credentials and set `stsToken.expiration`.
5. Treat `extraMetadata` as provider-defined routing/scoping input — EPE passes it through verbatim and never interprets it.
