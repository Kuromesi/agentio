# EPE configuration

The Egress Policy Enforcer (EPE) is deployed by the Agentio chart as `agentio-epe` when `epe.enabled` is true. This reference separates the Helm surface from EPE process settings so operators can see which controls a normal chart upgrade can change.

## Helm values

| Value | Default | Rendered effect |
| --- | --- | --- |
| `epe.enabled` | `false` | Creates the EPE ServiceAccount, cluster RBAC, headless Service, Deployment, and PodDisruptionBudget. It also writes `sandboxExtProc` into `agentio-config`. |
| `epe.name` | `agentio-epe` | Names the Kubernetes objects and the generated ext_proc Service hostname. |
| `epe.port` | `9002` | Service, container, EPE `-grpc-port`, and `sandboxExtProc.port`. |
| `epe.image.hub`, `.name`, `.tag` | `docker.io/openkruise`, `agentio-epe`, `latest` | EPE container image. The non-empty component hub wins; clear `epe.image.hub` to use `global.hub` as its fallback. |
| `epe.credentialProvider.url` | empty | Credential provider base URL, rendered as `IDENTITY_PROVIDER_URL`. Credential lookups fail while it is empty. |
| `epe.credentialProvider.mtls.source` | `files` | The one source of credential-provider mTLS material: `files`, `secret`, or `none`. Always rendered as `CREDENTIAL_PROVIDER_MTLS_SOURCE`. Any other value fails rendering. |
| `epe.credentialProvider.mtls.secretName` | empty | `source=files` only. Secret mounted at `/etc/epe/credential-provider`; empty means `<epe.name>-mtls-client-cert`. The chart never creates it. |
| `epe.credentialProvider.mtls.secret.namespace`, `.name` | empty | `source=secret` only. The Secret EPE watches directly. Both are required for that source; rendering fails if either is missing. |
| `epe.credentialProvider.mtls.insecureSkipVerify` | `false` | Rendered only when `true`. Disables provider server-certificate verification — exposes the bearer token to an on-path attacker. |
| `epe.env` | `{}` | Adds arbitrary string environment variables to the container after the chart-managed variables, so a key set here overrides the same chart-managed variable. |
| `epe.replicas` | `1` | Deployment replica count when autoscaling is disabled. |
| `epe.autoscaling.enabled` | `false` | Creates an HPA instead of setting Deployment replicas. |
| `epe.autoscaling.minReplicas`, `.maxReplicas` | `2`, `50` | HPA bounds when enabled. |
| `epe.autoscaling.targetCPUUtilizationPercentage` | `80` | Adds the CPU utilization metric when non-zero. |
| `epe.autoscaling.targetMemoryUtilizationPercentage` | unset | Adds the memory utilization metric only when set and non-zero. |
| `epe.autoscaling.behavior` | unset | Copies HPA scale behavior when set. |
| `epe.resources` | CPU `2`, memory `2Gi` requests and limits | Container resources. |
| `epe.pdbMinAvailable` | `1` | PodDisruptionBudget minimum available Pods. |
| `epe.nodeSelector`, `.tolerations`, `.affinity` | empty | Pod placement settings. |
| `epe.messageTimeout` | `5s` when unset | Template-supported value used for generated `sandboxExtProc.messageTimeout`; it is not declared in the default values file. |

The chart has no dedicated value for EPE command-line flags other than the three listener ports it supplies as container arguments. Use `epe.env` only for EPE environment variables. It cannot set a Go flag such as `--enable-pprof` or `--tls-cert-path`; those settings are binary-only unless you add container arguments through an authorized deployment customization.

## Rendered Kubernetes behavior

The Service is headless (`clusterIP: None`) and exposes TCP ports named `extproc` (`epe.port`), `health` (`9003`), and `metrics` (`9090`). Its selector matches `app.kubernetes.io/name: <epe.name>`. The Deployment disables Istio sidecar injection with `sidecar.istio.io/inject: "false"`, adds Prometheus scrape annotations for port 9090, and configures gRPC liveness and readiness probes against port 9003. Liveness starts after five seconds and runs every ten seconds; readiness starts after three seconds and runs every five seconds.

The chart grants the ServiceAccount `get/list/watch` on `SecurityProfile` and `GlobalSecurityProfile`, but only `get` on their status subresources. It also grants `get/list/watch` on CRDs, ConfigMaps, and Secrets. EPE needs the CRD watch before its delayed profile informers can synchronize; without it the process cannot complete startup.

With the default `epe.credentialProvider.mtls.source=files`, the Pod mounts an optional Secret at `/etc/epe/credential-provider` — `epe.credentialProvider.mtls.secretName`, defaulting to `<epe.name>-mtls-client-cert`. The chart does not create that Secret. That mount is for the credential-provider client; it does not enable TLS on the ext_proc listener. An empty mount leaves the credential client with no client certificate, verifying the provider against the system trust store; because the mount is watched, the Secret appearing later takes effect without a restart. Setting the source to `secret` or `none` omits the volume and its mount entirely.

## Agentio ext_proc wiring

When EPE is enabled, `agentio-config` contains:

```yaml
sandboxExtProc:
  service: agentio-epe.agentio-system.svc.cluster.local
  port: 9002
  messageTimeout: 5s
  request:
    headerMode: SEND
    attributes:
    - filter_state['sandbox.id']
    - filter_state['sandbox.token']
    - filter_state['sandbox.labels']
    - filter_state['downstream_peer'].name
    - filter_state['downstream_peer'].namespace
    - destination.port
    - source.address
  response:
    headerMode: SKIP
```

The service name uses the chart namespace, so `agentio-system` above is only the standard installation namespace. `agentioConfig` deep-merges over this chart-generated ConfigMap, and `agentio-config-primary`, if present, has runtime precedence. A per-gateway `egressGateways[].extProc` replaces the global `sandboxExtProc`; an explicitly empty gateway provider disables external processing for that gateway. See [Agentio configuration](agentio-configuration.md) for ConfigMap precedence and provider fields.

The generated provider leaves `failureModeAllow` unset, so its effective default is `false`. An unavailable EPE service, gRPC processing error, or ext_proc message timeout therefore fails the gateway request closed. Setting `agentioConfig.sandboxExtProc.failureModeAllow: true` keeps traffic moving but bypasses all EPE enforcement during those failures. A per-gateway override can choose differently through `egressGateways[].extProc.failureModeAllow`, but it must also repeat the complete provider service, port, modes, attributes, and timeout because the gateway provider replaces the global one. This provider outage setting is separate from a matched token transformation's `failStrategy`, which handles request-time transformation failures after EPE has received and projected the policy.

The generated `5s` message timeout must remain above EPE's default `--plugin-budget=4.5s`. An EPE action that exceeds its plugin budget follows that action's failure policy. If Envoy itself reaches the ext_proc message timeout, the provider-level `failureModeAllow` behavior above applies. A response header mode of `SKIP` means EPE does not receive upstream response headers by default.

## Process flags and listeners

| Flag | Default | Purpose |
| --- | --- | --- |
| `--grpc-port` | `9002` | ext_proc gRPC listener. The chart sets it from `epe.port`. |
| `--grpc-health-port` | `9003` | gRPC health listener used by Kubernetes probes. |
| `--metrics-port` | `9090` | HTTP listener serving only `/metrics`. |
| `--admin-addr` | `127.0.0.1:15000` | Admin HTTP bind address. |
| `--enable-debug` | `true` | Registers the `/debug/profiles` admin endpoint. |
| `--enable-pprof` | `false` | Starts Go pprof on `--pprof-addr`. |
| `--pprof-addr` | `:6060` | pprof listener address when enabled. |
| `--observe-responses` | `false` | Requests response headers through ext_proc so audit can record upstream status. |
| `--plugin-budget` | `4.5s` | Per-evaluation-phase limit; `0` disables it. Keep it below Envoy's ext_proc message timeout. |
| `--kubeconfig` | empty | Kubeconfig path; empty selects in-cluster configuration. |
| `--v` | `2` | Log verbosity unless `--zap-log-level` is supplied. |
| `--audit-log-buffer-size` | `4096` | Access-log queue capacity; full queues drop entries. |
| `--audit-webhook-buffer-size` | `8192` | Audit-webhook queue capacity; full queues drop events. |
| `--audit-webhook-workers` | `96` | Audit-webhook worker count. |
| `--audit-webhook-insecure-skip-verify` | `true` | Skips TLS certificate verification for every HTTPS audit webhook. |

The binary also accepts controller-runtime Zap flags, including `--zap-log-level` and `--zap-stacktrace-level`. The metrics and health listeners bind all interfaces because they are constructed from their port numbers. The chart exposes both through its headless Service. The admin listener is loopback-only by default and is not in that Service. pprof binds all interfaces by default when enabled; only enable it with an intentionally restricted bind address and network exposure.

## TLS for ext_proc

Without TLS flags, EPE serves plaintext ext_proc gRPC. This is the chart's default. Agentio's `ExtProcProvider` has no client-TLS fields, and the generated gateway ext_proc cluster is plaintext HTTP/2 with no TLS transport socket. Consequently, the Agentio-generated gateway cannot connect to an EPE listener after server TLS is enabled. Enabling only the EPE listener flags breaks the ext_proc connection and, with the default `failureModeAllow: false`, fails gateway requests closed. End-to-end ext_proc TLS currently requires a custom data-plane/xDS integration or a trusted intermediary that accepts the gateway's plaintext HTTP/2 connection and establishes TLS to EPE; neither is part of the chart or `AgentioConfig` surface.

| Flag | Requirement and behavior |
| --- | --- |
| `--tls-cert-path`, `--tls-key-path` | Must be set together. They load the serving certificate and key from PEM files and enable server TLS. The certificate/key pair hot-reloads after file events and a 10-second polling backstop. |
| `--tls-ca-path` | Requires the serving certificate and key. It enables required, CA-verified client certificates; the CA bundle is re-read on every handshake. |
| `--peer-spiffe-ids` | Comma-separated exact SPIFFE IDs. Requires `--tls-ca-path` and restricts verified client certificate URI SANs to the supplied IDs. |

Invalid combinations, unreadable initial certificate/key files, or an invalid initial CA bundle fail EPE startup. A failed later certificate reload keeps the last good certificate. Neither the chart's optional credential-client Secret nor `epe.env` configures these flags directly.

## Credential-provider and webhook environment variables

`IDENTITY_PROVIDER_URL`, `TOKEN_CACHE_TTL=3h`, and `TOKEN_CACHE_MAX_SIZE=10000` are set by the chart. The `CREDENTIAL_PROVIDER_*` mTLS variables come from the typed `epe.credentialProvider.mtls` values described below. Everything else uses `epe.env` (or a non-chart deployment):

| Variable | Default | Purpose |
| --- | --- | --- |
| `CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY` | `false` | Disables credential-provider server certificate verification; an on-path attacker can read the bearer token and forge a response. |
| `CREDENTIAL_PROVIDER_MTLS_SOURCE` | `files` | The single source of credential-provider mTLS material: `files`, `secret`, or `none`. There is no fallback between sources. An unrecognized value fails startup, and the chart rejects one at `helm template` time. Set through `epe.credentialProvider.mtls.source`, which the chart always renders explicitly. |
| `CREDENTIAL_PROVIDER_CLIENT_CERT_PATH` | `/etc/epe/credential-provider/client.crt` | Credential-provider client certificate path; read by the `files` source. |
| `CREDENTIAL_PROVIDER_CLIENT_KEY_PATH` | `/etc/epe/credential-provider/client.key` | Credential-provider private key path; read by the `files` source. |
| `CREDENTIAL_PROVIDER_CA_CERT_PATH` | `/etc/epe/credential-provider/ca.crt` | Credential-provider server CA path; read by the `files` source. |
| `CREDENTIAL_PROVIDER_SECRET_NAMESPACE`, `CREDENTIAL_PROVIDER_SECRET_NAME` | empty | Secret holding the credential-provider mTLS material, from `epe.credentialProvider.mtls.secret.namespace` / `.name`. Both are required when the source is `secret` — rendering fails if either is missing, as does startup; ignored otherwise. |
| `STS_CACHE_MAX_SIZE` | `100000` | Maximum cached STS credentials; non-positive values use the default. |
| `AUDIT_WEBHOOK_MAX_IDLE_CONNS` | `256` | Maximum idle audit-webhook connections across hosts. |
| `AUDIT_WEBHOOK_MAX_IDLE_CONNS_PER_HOST` | `64` | Maximum idle audit-webhook connections per host. |
| `AUDIT_WEBHOOK_MAX_CONNS_PER_HOST` | `128` | Maximum audit-webhook connections per host. |
| `AUDIT_WEBHOOK_IDLE_CONN_TIMEOUT` | `90s` | Audit-webhook idle connection timeout. |
| `AUDIT_WEBHOOK_TLS_HANDSHAKE_TIMEOUT` | `5s` | Audit-webhook TLS handshake timeout. |
| `AUDIT_WEBHOOK_RESPONSE_HEADER_TIMEOUT` | `10s` | Audit-webhook response-header timeout. |
| `AUDIT_WEBHOOK_EXPECT_CONTINUE_TIMEOUT` | `1s` | Audit-webhook `100-continue` wait. |
| `AUDIT_WEBHOOK_DIAL_TIMEOUT` | `5s` | Audit-webhook TCP dial timeout. |
| `AUDIT_WEBHOOK_DIAL_KEEPALIVE` | `30s` | Audit-webhook TCP keepalive interval. |

The credential client draws its mTLS material from the one source named by `CREDENTIAL_PROVIDER_MTLS_SOURCE`, never from a chain of them; whenever that source has no usable material the client presents no certificate and verifies the provider against the system trust store. See the [credential provider contract](credential-provider.md) for its request and caching behavior.

## Scaling and availability

The default single replica and `minAvailable: 1` PDB provide no disruption headroom. Raise replicas and set a compatible PDB before planned maintenance. When HPA is enabled, its CPU utilization metric is based on requests, so the chart's equal CPU request and limit are deliberate. EPE keeps compiled profiles in memory per Pod; each replica independently watches the Kubernetes API and serves the same policy objects.

Audit queues, credential calls, and plugin execution are local to each Pod. Scaling can reduce queue pressure and request latency, but it does not provide audit delivery persistence or retries. For operational signals, see [EPE observability](epe-observability.md).

## See also

- [Agentio configuration](agentio-configuration.md)
- [EPE observability](epe-observability.md)
- [EPE admin API](epe-admin-api.md)
- [Configure EPE audit events](../tasks/configure-epe-audit.md)
