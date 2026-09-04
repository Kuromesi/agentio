# Agentio Helm chart

Agentio is installed as one Helm release. The `profile` value selects the data
plane, while egress gateway and EPE use explicit modes.

```yaml
profile: ambient # ambient | sidecar

egressGateway:
  mode: disabled # disabled | static | gatewayAPI

epe:
  mode: disabled # disabled | managed | external
```

## Prerequisites

- Kubernetes and Helm 3.6 or later (Helm 4 is supported).
- Install the [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api)
  before selecting `egressGateway.mode=gatewayAPI`.
- Install the [Kruise Agents API](https://github.com/openkruise/agents-api)
  `sandboxes.agents.kruise.io` CRD before using Sandbox-backed policy.

The chart installs the four Agentio policy CRDs. Helm retains resources from
the chart's `crds/` directory when the release is uninstalled.

## Ambient mode

Ambient is the default profile. It installs `agentiod`, the Agentio CNI node
agent, and the node ztunnel:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  --namespace agentio-system \
  --create-namespace \
  --atomic \
  --wait
```

Enroll a workload namespace after the release is ready:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=ambient --overwrite
kubectl rollout restart deployment -n demo
```

## Sidecar mode

Sidecar mode installs `agentiod` and its injection webhook, without the ambient
CNI or node ztunnel:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  --namespace agentio-system \
  --create-namespace \
  --set profile=sidecar \
  --atomic \
  --wait
```

Enable injection and recreate workloads:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=sidecar --overwrite
kubectl rollout restart deployment -n demo
```

In this chart, `sidecar` means the existing Agentio per-Pod ztunnel injection
path. It is not a traditional Envoy sidecar.

## Egress gateway

The default mode is disabled. Static mode renders one gateway workload in the
same release:

```yaml
egressGateway:
  mode: static
  replicaCount: 2
```

```bash
helm upgrade --install agentio manifests/charts/agentio \
  -n agentio-system --create-namespace \
  -f values-prod.yaml --atomic --wait
```

Gateway API mode enables the `agentiod` Gateway Deployer. It can either watch
Gateway objects managed elsewhere or create one Gateway from chart values:

```yaml
egressGateway:
  mode: gatewayAPI
  gatewayAPI:
    create: true
    name: agentio-egress
    gatewayClassName: agentio-egress
    listeners:
      - name: mesh
        port: 15008
        protocol: HBONE
```

This mode requires the external Gateway API CRDs. The controller creates and
accepts the built-in `agentio-egress` GatewayClass.

## EPE

Managed mode deploys EPE and automatically writes its endpoint into the
control-plane Agentio configuration:

```yaml
epe:
  mode: managed
  auditWebhook:
    insecureSkipVerify: false
  credentialProvider:
    url: https://credentials.example.com
    mtls:
      source: files # files | secret | none
```

HTTPS audit webhooks verify the receiver certificate by default. Keep
`epe.auditWebhook.insecureSkipVerify: false` in production.

For `source: files`, the default Secret name is
`agentio-epe-mtls-client-cert`. Set `secretName` to override it. For
`source: secret`, configure the credential provider's source Secret:

```yaml
epe:
  mode: managed
  credentialProvider:
    url: https://credentials.example.com
    mtls:
      source: secret
      secret:
        namespace: credential-system
        name: epe-client
```

External mode deploys no EPE workload and points the control plane and static
gateway at an existing endpoint:

```yaml
epe:
  mode: external
  external:
    address: epe.security-system.svc
    port: 9002
```

User settings under `agentiod.config.values` override the generated
`sandboxExtProc` defaults when custom request or response behavior is needed.

## Logging

Agentiod emits structured logs through Go's `log/slog`. Text output at info
level is the default; JSON is recommended for production log collectors:

```yaml
agentiod:
  logging:
    level: info # debug | info | warn | error
    format: json # text | json
```

The chart maps these values to `AGENTIO_LOG_LEVEL` and
`AGENTIO_LOG_FORMAT`. Standard-library logs and Kubernetes `klog` output use
the same handler and format.

## Upgrades and profile changes

Keep release values in a file and use the same command for installation and
upgrade:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  -n agentio-system \
  -f values-prod.yaml \
  --atomic \
  --wait
```

This is one Helm release. Component image tags can be set independently, but
the release has one values set and one rollback history. Helm does not wait for
`agentiod` before creating the CNI, ztunnel, gateway, or EPE resources;
readiness and client retries provide convergence, and `--wait` waits for the
whole release.

Changing `profile` does not relabel namespaces or recreate business Pods. For
sidecar to ambient, switch the dataplane-mode label and restart the workloads
after the upgraded Agentio release is ready:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=ambient --overwrite
kubectl rollout restart deployment -n demo
```

For ambient to sidecar, switch the label back and restart:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=sidecar --overwrite
kubectl rollout restart deployment -n demo
```

Profile switching is not currently an ordered, zero-downtime migration.

## Local verification

```bash
sh manifests/charts/verify.sh
```

This lints the unified chart, runs its render contract tests, and runs the
complete Go test suite.
