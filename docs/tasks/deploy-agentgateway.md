# Deploy agentgateway with the Gateway API

Agentio's gateway deployer supports the `agentio-agentgateway` GatewayClass. It provisions a ServiceAccount, Deployment, and Service, and runs agentgateway with a native YAML configuration file supplied through a ConfigMap.

This class currently provides deployment management only. It does not translate HTTPRoute, SecurityProfile, EnvoyFilter, or Agentio egress configuration into agentgateway configuration. Sandbox identity and dynamic SNI policies are not supported by this path. Existing `agentio-egress` Gateways continue to use Envoy.

## Enable the deployer

Install Gateway API CRDs, then enable `egressGateway.mode: gatewayAPI` in the Agentio Helm release. The controller creates the `agentio-agentgateway` class with controller name `agentio.kruise.io/agentgateway-controller`.

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    image: cr.agentgateway.dev/agentgateway:v1.5.0
    replicaCount: 1
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "2", memory: 1Gi}
```

The image is an operator-controlled value; a Gateway annotation cannot override it. Scheduling can be configured with `egressGateway.agentgateway.nodeSelector`, `tolerations`, `affinity`, and `topologySpreadConstraints`.

The injector ConfigMap contains both the `egress-gateway` and `agentgateway` deployment templates. Older injector ConfigMaps without the new template remain usable for Envoy; an agentgateway Gateway reports an error until its template is installed.

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

To configure an egress gateway, replace the example body with native agentgateway CONNECT/internal-listener configuration and corresponding Gateway ports. The deployment controller does not automatically connect application or ztunnel traffic to this gateway.

If Helm should also create the Gateway, set `egressGateway.gatewayAPI.create: true`, `gatewayClassName: agentio-agentgateway`, and `infrastructure.parametersRef` under `egressGateway.gatewayAPI`. The referenced ConfigMap remains operator-owned.

## Mount certificates

For configurations requiring TLS certificates or a MITM CA, reference a Secret in the Gateway namespace:

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agentgateway-certs: agentgateway-certs
```

The Secret's keys are mounted as files beneath `/etc/agentgateway/certs`. Use those paths in `config.yaml`. The deployer does not issue certificates, read Secret contents, or manage Secret rotation. After rotating certificates, explicitly roll the Deployment to ensure the process reloads them. Clients must trust the appropriate server/MITM CA; upstream TLS verification is configured in the native file.

File mode does not connect to Agentiod's xDS/CA endpoints or mount Kubernetes service-account tokens. The proxy runs as a non-root user with a read-only root filesystem.

## Updates and status

Updating the referenced `config.yaml` triggers reconciliation and changes the Pod template's `gateway.agentio.kruise.io/config-hash` annotation. The configuration is mounted with `subPath`, so existing Pods keep their loaded file during the rollout. The Deployment uses `maxUnavailable: 0` and `maxSurge: 1`.

- Missing references, empty configuration, or invalid YAML report `Accepted=False` and `Programmed=False`, without replacing the Deployment configuration.
- YAML syntax is checked by Agentio; agentgateway validates its configuration schema during startup. A schema-invalid configuration can create a failing new Pod while the old replica continues serving. Correct the ConfigMap to recover.
- `Programmed=True` means the desired configuration's Deployment rollout is available. It does not assert HTTPRoute attachment, policy enforcement, or end-to-end application connectivity.
- Removing the Gateway allows Kubernetes to garbage-collect its owned Deployment, Service, and ServiceAccount. ConfigMaps and Secrets are not adopted or deleted.

```bash
kubectl -n agentio-system get gateway agentgateway -o yaml
kubectl -n agentio-system rollout status deployment/agentgateway
kubectl -n agentio-system logs deployment/agentgateway
```

The class/template structure and the proxy security context and probes are adapted from [Istio 1.31's deployment controller](https://github.com/istio/istio/blob/1.31.0/pilot/pkg/config/kube/gatewaycommon/deploymentcontroller.go) and [agentgateway template](https://github.com/istio/istio/blob/1.31.0/manifests/charts/istio-control/istio-discovery/files/agentgateway.yaml). Agentio uses file configuration for this class, rather than Istio's xDS bootstrap.

## End-to-end coverage

The [standard agentgateway e2e suite](../../test/e2e/suites/agentgateway/README.md) installs the full production chart and exercises this controller with real ztunnel mTLS CONNECT traffic. It shares outbound protocol, ext-proc header mutation, and port-selection checks with the Envoy suite. The suite also covers 10 deployment/configuration lifecycle scenarios. Certificate issuance in this suite is a test fixture; it does not add a production certificate controller.
