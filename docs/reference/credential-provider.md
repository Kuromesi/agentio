# Credential Provider Contract

EPE's `tokenTransformation` action injects or re-signs credentials on egress requests so that long-lived secrets never enter the sandbox.
The credentials themselves come from a **credential provider**: an HTTP service that EPE calls at request time to exchange a sandbox's identity for a short-lived API key or STS triplet.

The credential provider is an **extension point, not a fixed backend**.
Any service that implements the contract below works; integrations that target a specific cloud vendor (for example an Alibaba Cloud-backed provider) are implementations of this same contract.
EPE ships the client side only (`extensions/epe/pkg/credential`).

## Request flow

```text
sandbox ──> egress gateway ──ext_proc──> EPE ──HTTPS/mTLS──> credential provider
                                          │
                                          └─ injects apiKey / signs with STS
```

1. The data plane attaches the caller's identity as `filter_state['sandbox.token']`: base64-encoded (or raw) JSON of

   ```json
   {"requestId": "...", "accessToken": "...", "sandboxClientId": "..."}
   ```

2. When a matched rule carries `tokenTransformation` with a `credentialRef.credentialProvider`, EPE calls the provider using `accessToken` as the bearer credential and `sandboxClientId` as the resource being acted for.

3. The provider authenticates the caller (mTLS client certificate and the bearer token), authorizes the `(resource, provider name)` pair, and returns the credential.

## Wire contract

One endpoint, configured by the `IDENTITY_PROVIDER_URL` environment variable (chart value `epe.identityProviderUrl`).
EPE sends:

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

Success response — `200 OK` with a JSON body.
Exactly one of the credential fields is expected, matching the requested `credentialType`:

```json
{ "requestId": "...", "apiKey": "sk-..." }
```

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

Failure response — any non-200 status.
The body is logged and surfaced in the error.
EPE does not retry; the failure resolves through the matched rule's `failStrategy` (block the request or pass it through unmodified).

## Transport security

EPE presents a client certificate when mTLS material is available, in this priority order:

1. Kubernetes Secret named by `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `CREDENTIAL_PROVIDER_SECRET_NAME` with data keys `ca.crt`, `client.crt`, `client.key` (the chart mounts `<name>-mtls-client-cert`).
2. File paths from `CREDENTIAL_PROVIDER_CLIENT_CERT_PATH` / `CREDENTIAL_PROVIDER_CLIENT_KEY_PATH` / `CREDENTIAL_PROVIDER_CA_CERT_PATH` (defaults: `/etc/epe/mtls/{client.crt,client.key,ca.crt}`).
3. Fallback: TLS without a client certificate, verified against the system trust store. Verification is never skipped; TLS 1.2 is the minimum.

Providers should require the client certificate and treat the bearer `accessToken` as the per-sandbox authorization, not as the only authentication factor.

## Caching semantics

Providers must tolerate credential reuse within a bounded window; EPE caches per `(providerName + hash(extraMetadata), resourceId)`:

| Credential | Lifetime | Size bound |
| --- | --- | --- |
| `apiKey` | `TOKEN_CACHE_TTL` (chart default `3h`) | `TOKEN_CACHE_MAX_SIZE` |
| `stsToken` | until `stsToken.expiration` (uncacheable without it) | `STS_CACHE_MAX_SIZE` |

Practical consequences:

- Key rotation on the provider side becomes visible to EPE only after the cache entry expires; pick `TOKEN_CACHE_TTL` accordingly.
- Returning `expiration` on STS responses is strongly recommended — it is the only way the provider controls STS reuse.

## Environment variable reference

| Variable | Meaning |
| --- | --- |
| `IDENTITY_PROVIDER_URL` | Provider endpoint; unset means provider-backed rules fail through `failStrategy` |
| `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `_NAME` | Secret holding mTLS material |
| `CREDENTIAL_PROVIDER_CLIENT_CERT_PATH` / `_KEY_PATH` / `_CA_CERT_PATH` | File fallbacks for mTLS material |
| `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE` | API-key cache tuning |
| `STS_CACHE_MAX_SIZE` | STS cache tuning |

## Implementing a provider

A conforming provider must:

1. Serve `POST` on a single HTTPS endpoint and read `X-Api-Action-Name: GetResourceCredential`.
2. Authenticate the mTLS client certificate and the `Authorization: Bearer` token; authorize the `(resourceId, credentialProviderName)` pair.
3. Return `200` with `apiKey` or a complete `stsToken` per the requested `credentialType`; return a non-200 status with a diagnostic body otherwise.
4. Issue short-lived credentials and set `stsToken.expiration`.
5. Treat `extraMetadata` as provider-defined routing/scoping input — EPE passes it through verbatim and never interprets it.
