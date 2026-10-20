# Configure OAuth credential isolation

Use `tokenTransformation.type: OAuth2` to keep real third-party application secrets, access tokens, refresh tokens, and upstream device codes outside a Sandbox. EPE brokers the client's OAuth requests through a trusted credential service and injects real Bearer credentials only into selected resource requests. The public API comes from `openkruise/agents-api`; both SecurityProfile kinds use the same configuration.

## Prerequisites

- Route the selected Sandbox's traffic through an EPE-enabled trusted gateway.
- Apply OAuth policies to decrypted inner HTTPS requests. EPE rejects plaintext HTTP, missing schemes, and CONNECT envelopes before credential lookup. The gateway must verify the destination and upstream TLS certificate.
- Configure the default credential connection in [EPEConfig](../reference/epe-configuration.md). `credentialRef.credentialProvider.name` selects the remote business provider; it does not select a local connection or accept provider parameters.
- Supply the trusted platform token and Sandbox client ID through the existing [request identity chain](../reference/epe-request-context.md). CLI placeholders cannot override that identity.

## Operations and responses

Each `oauth2.operation` contains exactly one branch:

| Branch | Behavior |
| --- | --- |
| `deviceAuthorization: {}` | Creates a session and returns public verification information and a broker handle in `device_code`. A service-confirmed existing authorized session is accepted without another verification URI. |
| `token: {}` | Parses Form or JSON according to Content-Type, handles `grant_type`, and returns `unused` token placeholders with available scope/expiry metadata. |
| `resource: {}` | Retrieves the current authorized credential, overwrites Authorization, and forwards the original request. EPE does not request the business body or rewrite the upstream response. |

Token may set `allowedGrantTypes` to an exact string set. Omitted or empty adds no policy restriction; it does not add backend capabilities. There is no `requestFormat`, request-parameter map, service action, or authorized-session option. The existing Identity integration supports device authorization, device-code polling, and current-token retrieval/refresh. Other token grants return `unsupported_grant_type` without invoking a device API.

`customResponse` is optional and belongs alongside `operation`. `error` adds application fields to generated OAuth errors. `authorizationRequired` adds fields after a confirmed non-retryable authorization requirement, overriding matching application fields in `error`. `success` applies only to Token. Extensions must be public JSON objects; standard OAuth fields cannot be replaced. When omitted, responses contain only the generated protocol fields.

EPE rejects invalid operation combinations, response fields, and credential configuration when compiling the profile. OAuth requires the default Block failure strategy; Allow and Ignore are not supported. Runtime failures return OAuth errors and stop forwarding.

## Example: lark-cli

Configure the `lark-cli` business provider in the credential service first. Change the namespace and selector to match your Sandbox. Two Token rules are used because this CLI's JSON refresh handler requires numeric response codes; both use the same Content-Type decoder. The JSON rule precedes the general Token rule because a local Token response ends policy processing.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: lark-oauth2
  namespace: agent-demo
spec:
  selector:
    matchLabels: {app: agent}
  rules:
    - name: device-authorization
      match:
        - domains: [accounts.feishu.cn]
          paths: [{type: Exact, value: /oauth/v1/device_authorization}]
          methods: [POST]
          schemes: [https]
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {deviceAuthorization: {}}
    - name: json-refresh
      match:
        - domains: [open.feishu.cn]
          paths: [{type: Exact, value: /open-apis/authen/v2/oauth/token}]
          methods: [POST]
          schemes: [https]
          headers:
            - name: content-type
              type: Regex
              value: '(?i)^application/json(?:\s*;.*)?$'
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {token: {}}
            customResponse:
              success: {code: 0}
              error: {code: 20050}
              authorizationRequired: {code: 20026}
    - name: standard-token
      match:
        - domains: [open.feishu.cn]
          paths: [{type: Exact, value: /open-apis/authen/v2/oauth/token}]
          methods: [POST]
          schemes: [https]
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {token: {}}
    - name: reject-app-registration
      match:
        - domains: [accounts.feishu.cn]
          paths: [{type: Exact, value: /oauth/v1/app/registration}]
          methods: [POST]
      actions:
        block:
          statusCode: 403
          body: '{"error":"access_denied","error_description":"Application registration is managed by the credential service."}'
    - name: document-business
      match:
        - domains: [open.feishu.cn]
          schemes: [https]
          paths:
            - {type: Exact, value: /open-apis/authen/v1/user_info}
            - {type: Prefix, value: /open-apis/docx/}
            - {type: Prefix, value: /open-apis/docs_ai/}
            - {type: Prefix, value: /open-apis/wiki/}
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {resource: {}}
            customResponse:
              authorizationRequired:
                code: 99991663
                msg: 'User authorization is required. Run lark-cli auth login.'
```

The domains, paths, numeric codes, and registration restriction are deployment policy. The EPE implementation does not infer operations from Feishu URLs. For a GlobalSecurityProfile, change the kind and omit `metadata.namespace`.

## Verify the client path

Apply the profile, confirm EPE accepted its version, then run the unmodified CLI's login from the selected Sandbox. Complete the user verification step when required. Polling and refresh should return placeholder tokens; inspect the CLI's local state without printing real credentials. A selected business request should reach the intended upstream with a real Bearer credential while its body and the upstream response remain unchanged.

The test suite exercises published CRD admission, production policy projection, the provider registry, and the ext_proc gRPC chain against an HTTP credential service fixture. A live gateway/CLI deployment is a separate verification of the destination, TLS, and platform identity configuration.

## Authorization and cache boundaries

Authorization is per Sandbox, remote provider, and trusted platform identity. Clients sharing that binding use the same current authorization. `unused` is a compatibility placeholder, not a CLI session identifier. Clearing a CLI cache does not revoke authorization; replacing the binding can change the credential used by other clients sharing it. Independent CLI sessions, reliable CLI logout, and concurrent accounts require coordinated client/service contracts.

Resource caching stays in trusted EPE memory. Only a positive service `cacheExpiresInSeconds`, capped by the known access-token lifetime, permits reuse. Zero, missing, or negative cache TTL disables caching. The current Identity contract returns zero, so each matched business request still asks Identity for a credential; that lookup does not necessarily refresh the upstream token. Token and DeviceAuthorization always call the service and invalidate the binding's Resource entries. No cache TTL is configured in the SecurityProfile.
