# Deploy agentgateway with the Gateway API

Agentio's gateway deployer supports the `agentio-agentgateway` GatewayClass. It provisions a ServiceAccount, Deployment, Service, HorizontalPodAutoscaler (HPA), and PodDisruptionBudget (PDB), and runs agentgateway with a native YAML configuration file supplied through a ConfigMap.

This class provides deployment management and opt-in workload certificate bootstrap through Agentiod CA. It does not translate HTTPRoute, SecurityProfile, EnvoyFilter, or Agentio egress configuration into agentgateway configuration. Sandbox identity and dynamic SNI policies are not supported by this path. Existing `agentio-egress` Gateways continue to use Envoy.

## Enable the deployer

Install Gateway API CRDs, then enable `egressGateway.mode: gatewayAPI` in the Agentio Helm release. The controller creates the `agentio-agentgateway` class with controller name `agentio.kruise.io/agentgateway-controller`.

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    image: cr.agentgateway.dev/agentgateway:v1.5.0
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "2", memory: 1Gi}
```

The image is an operator-controlled value; a Gateway annotation cannot override it. Scheduling can be configured with `egressGateway.agentgateway.nodeSelector`, `tolerations`, `affinity`, and `topologySpreadConstraints`.

The injector ConfigMap contains both the `egress-gateway` and `agentgateway` deployment templates. Older injector ConfigMaps without the new template remain usable for Envoy; an agentgateway Gateway reports an error until its template is installed.

The generated HPA/PDB use Istio 1.31's template defaults: the HPA targets the Gateway Deployment with `maxReplicas: 1`, and the PDB specifies only the Gateway Pod selector. The Deployment template leaves `spec.replicas` unset.

## Supply file configuration

Create the configuration and Gateway in the same namespace. `parametersRef` must reference a core ConfigMap, and the configuration must be stored in `data["config.yaml"]`.

This example serves a fixed response to confirm deployment and configuration loading:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentgateway-config
  namespace: agentio-system
data:
  config.yaml: |
    config:
      adminAddr: 127.0.0.1:15000
    binds:
    - port: 8080
      listeners:
      - protocol: HTTP
        routes:
        - policies:
            directResponse:
              status: 200
              body: agentgateway is ready
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: agentio-system
spec:
  gatewayClassName: agentio-agentgateway
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: agentgateway-config
  listeners:
  - name: http
    port: 8080
    protocol: HTTP
```

The Gateway listeners determine the Service ports; the ConfigMap determines what the proxy actually listens on and how it routes. Keep them consistent. Keep readiness on port 15021 at `/healthz/ready` and metrics on port 15020 at `/metrics`, as expected by the deployment template.

To configure an egress gateway, replace the example body with the native HBONE/internal-listener configuration below and corresponding Gateway ports. The deployment controller does not automatically connect application or ztunnel traffic to this gateway.

If Helm should also create the Gateway, set `egressGateway.gatewayAPI.create: true`, `gatewayClassName: agentio-agentgateway`, and `infrastructure.parametersRef` under `egressGateway.gatewayAPI`. The referenced ConfigMap remains operator-owned.

## Obtain HBONE certificates from Agentiod

Enable the native Istio-compatible CA client for agentgateway deployments:

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    ca:
      enabled: true
```

This option defaults to `false` to preserve existing file/Secret deployments. It applies to all `agentio-agentgateway` Gateways managed by this installation. It enables certificate bootstrap only; routes still come from the referenced ConfigMap and no agentgateway xDS connection is configured.

Following Istio 1.31's bootstrap, the deployer supplies:

- `CA_ADDRESS`: the HTTPS Agentiod endpoint from the injector's `global.caAddress`. A scheme-less address is normalized to HTTPS; plaintext endpoints are rejected.
- `NAMESPACE` and `SERVICE_ACCOUNT`: downward API values from the Gateway Pod. The certificate identity is `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`, including any configured Gateway ServiceAccount override.
- `TRUST_DOMAIN` and `CLUSTER_ID`: the configured mesh identity values.
- `CA_AUTH_TOKEN`: a projected, 12-hour ServiceAccount token at `/var/run/secrets/tokens/istio-token`. Its audience uses `agentiod.tokenAudience`, as distributed through the injector values. Kubernetes refreshes the token and the native client rereads it when requesting certificates.
- `CA_ROOT_CA`: the public trust bundle at `/var/run/secrets/istio/root-cert.pem`, from `agentiod.ca.trustBundleConfigMapName` in the Gateway namespace. Agentiod's trust-bundle distributor creates and updates this ConfigMap. The directory mount allows projected updates.

The proxy generates its private key and CSR in memory and calls Agentiod's `IstioCertificateService/CreateCertificate`. Agentiod authenticates the token with TokenReview and restricts the CSR to that ServiceAccount's identity. The proxy does not read the CA Secret, mount a CA private key, create a leaf Secret, or need node impersonation privileges. Default Kubernetes token automount stays disabled.

Configure the HBONE bind in the native ConfigMap as follows, and expose port 15008 with `protocol: HBONE` in the Gateway listeners:

```yaml
binds:
- port: 15008
  tunnelProtocol: hboneGateway
  listeners:
  - protocol: HBONE
- port: 80
  mode: internal
  protocol: AUTO
  listeners: &egress-listeners
  - protocol: HTTP
    routes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TLS
    hostname: "*"
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TCP
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
- port: 443
  mode: internal
  protocol: AUTO
  listeners: *egress-listeners
```

`hboneGateway` performs mTLS with the native workload certificate, verifies the client's trust domain, and dispatches the CONNECT destination to an internal bind. It requires an IP:port CONNECT authority and an explicit internal bind for each destination port in v1.5.0; it does not match a port-less wildcard internal bind. The example permits ports 80 and 443. Add internal binds for other required ports; internal binds do not open Pod sockets or require corresponding Service ports. It does not expose the generic `connect` tunnel's `source.connectHeaders`; configurations relying on an outer Host override or synthetic destination addresses need a separate routing integration. This example forwards to the original destination IP and passes inner HTTPS through unchanged. Scope permitted destinations using your egress configuration and native gateway policies.

Use `hboneGateway` rather than keeping a `connect` + `tls.cert/key` bind: enabling the CA client alone does not replace certificates on static TLS listeners.

### Renewal and operational boundaries

The v1.5.0 native client requests a 24-hour certificate; Agentiod caps this at its configured workload certificate lifetime. The client checks every 30 seconds and renews at the certificate's midpoint. New connections use the updated certificate without a Deployment rollout; existing connections retain their negotiated TLS session.

The following upstream behaviors matter when operating this mode:

- A renewal failure replaces the cached certificate state with an error, even if the previous certificate has not expired. New HBONE connections fail until a retry succeeds. v1.5.0 does not provide last-valid-certificate fallback or jittered backoff.
- `/healthz/ready` and Gateway `Programmed` do not verify certificate availability. Monitor CA fetch/renewal failures and run an authenticated HBONE probe; a ready Pod alone is insufficient proof of mesh connectivity.
- The CA connection reads its root file for each certificate request, while peer trust roots come from the last successful CA response. Root replacement must keep old and new roots trusted throughout distribution and workload renewal. This change does not implement or validate a cross-root migration protocol.

## Mount additional or externally managed certificates

For configurations requiring TLS certificates or a MITM CA, reference a Secret in the Gateway namespace:

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agentgateway-certs: agentgateway-certs
```

The Secret's keys are mounted as files beneath `/etc/agentgateway/certs`. Use those paths in `config.yaml`. The deployer does not issue certificates, read Secret contents, or manage Secret rotation. After rotating certificates, explicitly roll the Deployment to ensure the process reloads them. Clients must trust the appropriate server/MITM CA; upstream TLS verification is configured in the native file.

External Secret mounts can coexist with native CA mode, for example for a separate HTTPS listener or MITM CA. When `ca.enabled` is false, the generated bootstrap has no CA connection or projected ServiceAccount token. The proxy runs as a non-root user with a read-only root filesystem.

## Updates and status

Updating the referenced `config.yaml` triggers reconciliation and changes the Pod template's `gateway.agentio.kruise.io/config-hash` annotation. The configuration is mounted with `subPath`, so existing Pods keep their loaded file during the rollout. The Deployment uses `maxUnavailable: 0` and `maxSurge: 1`.

- Missing references, empty configuration, or invalid YAML report `Accepted=False` and `Programmed=False`, without replacing the Deployment configuration.
- YAML syntax is checked by Agentio; agentgateway validates its configuration schema during startup. A schema-invalid configuration can create a failing new Pod while the old replica continues serving. Correct the ConfigMap to recover.
- `Programmed=True` means the desired configuration's Deployment rollout is available. It does not assert HTTPRoute attachment, policy enforcement, or end-to-end application connectivity.
- Deleted HPA/PDB resources are recreated by the deployer. Removing the Gateway allows Kubernetes to garbage-collect its owned Deployment, Service, ServiceAccount, HPA, and PDB. ConfigMaps and Secrets are not adopted or deleted.

```bash
kubectl -n agentio-system get gateway agentgateway -o yaml
kubectl -n agentio-system rollout status deployment/agentgateway
kubectl -n agentio-system logs deployment/agentgateway
```

The class/template structure and the proxy security context and probes are adapted from [Istio 1.31's deployment controller](https://github.com/istio/istio/blob/1.31.0/pilot/pkg/config/kube/gatewaycommon/deploymentcontroller.go) and [agentgateway template](https://github.com/istio/istio/blob/1.31.0/manifests/charts/istio-control/istio-discovery/files/agentgateway.yaml). Agentio uses file configuration for this class, rather than Istio's xDS bootstrap.

## End-to-end coverage

The [standard agentgateway e2e suite](../../test/e2e/suites/agentgateway/README.md) installs the full production chart and exercises this controller with real ztunnel mTLS CONNECT traffic. It shares outbound protocol, ext-proc header mutation, and port-selection checks with the Envoy suite. The suite also covers 12 deployment/configuration lifecycle scenarios, including HPA/PDB recreation and garbage collection. The suite enables native CA mode: the Gateway Pod obtains its certificate from Agentiod using its own projected token. The fixture does not read CA private keys or issue gateway leaf Secrets.

A separate local interoperability test runs a real v1.5.0 binary against Agentiod CA over TLS, with only the Kubernetes TokenReview API faked. It checks SPIFFE identity, mTLS CONNECT forwarding, refusal of unauthenticated clients, token refresh, certificate renewal without restart, and renewal failure/recovery:

```bash
AGENTIO_AGENTGATEWAY_BINARY=/absolute/path/to/agentgateway-v1.5.0 \
  go test ./pkg/security/ca -run TestAgentgatewayNativeCACertificateRotation -count=1 -v -timeout=3m
```
