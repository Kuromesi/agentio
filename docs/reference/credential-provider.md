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

EPEConfig supports multiple named credential services and selects the default through `defaultProviders.credentialProvider`. SecurityProfile's existing `name` field continues to select the remote credential configuration. Per-rule extension provider references are deferred to future SecurityProfile API work.

EPE converts `IDENTITY_PROVIDER_URL` (chart value `epe.credentialProvider.url`) and its related environment settings into a default EPEConfig containing a credential provider named `agentio-default-credential-provider` and the corresponding `defaultProviders` selection. An unset URL generates no provider. Base and primary ConfigMaps overlay this default configuration; provider lists merge by name, with same-name entries replaced in full. Adding only HTTPCallout providers preserves the environment credential provider. An explicit `extensionProviders: []` clears the inherited list, and deleting a ConfigMap restores the lower layer. The registry consumes only the resulting configuration; the environment-generated name is ordinary and can be overridden like any other. See [EPE configuration](epe-configuration.md#watched-epeconfig) for default selection and clearing semantics. The environment variable's name predates the credential-provider naming and is retained for compatibility. EPE sends:

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

`CREDENTIAL_PROVIDER_MTLS_SOURCE` selects the TLS source for the environment-derived default provider. It supports `none` and `secret`; file sources are configured through EPEConfig.

| Source | Where the material comes from |
| --- | --- |
| `secret` | The Secret named by `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `CREDENTIAL_PROVIDER_SECRET_NAME`, fixed data keys `ca.crt`, `tls.crt`, `tls.key`. Both variables are required. |
| `none` (default) | No client certificate; HTTPS uses the system trust store. |

Within the chosen source the client identity and the trust anchors are independent: a source may supply anchors without an identity, or an identity without anchors. Material that is absent or unusable means EPE presents no client certificate and verifies the provider against the system trust store; it is never a startup failure. Only a misconfigured source is — an unrecognized `CREDENTIAL_PROVIDER_MTLS_SOURCE` value, or `secret` without both a namespace and a name.

EPE watches sources referenced by the effective configuration, so material that appears or rotates after startup takes effect without a restart. A Secret that does not exist yet leaves no client identity for the optional environment-derived provider while EPE watches for its creation. The EPE ServiceAccount needs list/watch permission for Secrets, including any explicitly configured namespace. TLS 1.2 is the minimum in every case.

These settings become ordinary EPEConfig TLS fields: `caSecretRef` and `clientCertificateSecretRef`, each with an optional `namespace`. CA references read the fixed `ca.crt` data key; client references read the fixed `tls.crt` and `tls.key` data keys. These key names cannot be overridden, including for environment-derived default providers. Existing Secrets using `client.crt` and `client.key` must rename those entries to `tls.crt` and `tls.key`. Missing or empty entries are unavailable material, subject to `tls.optional` as described below.

For server-only TLS, omit client identity fields. An HTTPS URL without TLS settings uses system roots. To use a ConfigMap trust bundle, place the PEM CA certificates in its fixed `data["ca.crt"]` entry and configure:

```yaml
tls:
  caConfigMapRef:
    name: provider-ca
    namespace: security-system
```

The namespace defaults to the EPEConfig namespace. EPE watches this ConfigMap for creation, updates, and deletion. No client certificate or `optional: true` setting is required for server-only TLS.

Both `credentialProvider.tls` and `httpCallout.tls` also accept PEM file paths in EPEConfig:

```yaml
extensionProviders:
- name: corporate
  credentialProvider:
    url: https://credentials.example
    tls:
      caCertificateFile: /etc/epe/certs/ca.crt
      clientCertificateFiles:
        certificateFile: /etc/epe/certs/tls.crt
        privateKeyFile: /etc/epe/certs/tls.key
defaultProviders:
  credentialProvider: corporate
```

Paths refer to files inside the EPE container; the deployment must provide them. EPEConfig does not create volume mounts. Changing a configured path updates its watch, and file contents reload on filesystem events with a 10-second polling backstop, including when a directory appears after startup. The CA source is a oneof: `caSecretRef`, `caConfigMapRef`, or `caCertificateFile`. The client identity source is a separate oneof: `clientCertificateSecretRef` or `clientCertificateFiles`, whose `certificateFile` and `privateKeyFile` are both required. Each group permits at most one source; CA and client identity sources can be mixed independently.

Environment defaults set `tls.optional: true`: unavailable or invalid client material is dropped, and unavailable or invalid CA material falls back to system roots. Explicit EPEConfig TLS sources are strict unless marked optional; invalidating a required source makes the provider unavailable and prevents serving its cached credentials.

`CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY=true` is an explicit exception for trusted test environments: it disables provider server-certificate verification while retaining any configured client certificate. It exposes the bearer token and returned credentials to an on-path attacker and must not be used in production.

Providers should require the client certificate and treat the bearer `accessToken` as the per-sandbox authorization, not as the only authentication factor.

## Caching semantics

Providers must tolerate credential reuse within a bounded window; EPE caches per `(providerName + hash(extraMetadata), resourceId)`:

Each registered credential provider has its own caches. `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE`, and `STS_CACHE_MAX_SIZE` are read at process startup and apply to all credential providers, including those added later through EPEConfig. Capacity limits are per provider, not a shared process-wide budget. Changing these environment variables requires restarting EPE; EPEConfig does not expose cache settings.

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
| `CREDENTIAL_PROVIDER_MTLS_SOURCE` | The single source of mTLS material: `none` (default) or `secret` |
| `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `_NAME` | Secret holding mTLS material; both required by the `secret` source |
| `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE` | API-key cache tuning; `TOKEN_CACHE_TTL` is the fallback lifetime for responses without `cacheExpiresInSeconds` |
| `STS_CACHE_MAX_SIZE` | STS cache tuning |

## Implementing a provider

A conforming provider must:

1. Serve `POST` on a single HTTPS endpoint and read `X-Api-Action-Name: GetResourceCredential`.
2. Authenticate the mTLS client certificate and the `Authorization: Bearer` token; authorize the `(resourceId, credentialProviderName)` pair.
3. Return `200` with `apiKey` or a complete `stsToken` per the requested `credentialType`; return a non-200 status with a diagnostic body otherwise.
4. Issue short-lived credentials and set `stsToken.expiration`.
5. Treat `extraMetadata` as provider-defined routing/scoping input — EPE passes it through verbatim and never interprets it.
