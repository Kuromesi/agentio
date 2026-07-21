# Get started with sidecar mode

This guide installs Agentio with per-Pod sidecar injection, enrolls a sample workload, and prepares the workload for the shared egress gateway and `TrafficPolicy` tasks.

## Before you begin

You need:

- A Kubernetes cluster that you can administer.
- `kubectl` configured for that cluster.
- Helm 3.
- A local clone of this repository.
- Access to the container images configured in [`manifests/charts/agentio/values.yaml`](../../manifests/charts/agentio/values.yaml).

Run the commands in this guide from the repository root.

Agentio uses the standard `istio-injection` and `sidecar.istio.io/inject` selectors. If the cluster already runs Istio or another injector that watches these selectors, review the existing namespace labels and mutating webhooks before you continue:

```console
$ kubectl get namespace -L istio-injection,istio.io/rev,istio.io/dataplane-mode
$ kubectl get mutatingwebhookconfigurations
```

## Install Agentio in sidecar mode

Create an explicit sidecar-mode values file:

```console
$ cat >/tmp/agentio-sidecar-values.yaml <<'EOF'
sidecarInjector:
  enabled: true
ambient:
  enabled: false
EOF
```

Install Agentio from this repository:

```console
$ helm upgrade --install agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --values /tmp/agentio-sidecar-values.yaml \
    --wait \
    --timeout 5m
```

Some default Agentio images use `docker.io/openkruise` and mutable `latest` tags. Review every image value and override it when your environment uses a private registry or pinned release images.

Verify the control plane and Agentio APIs:

```console
$ kubectl rollout status deployment/agentiod \
    --namespace agentio-system \
    --timeout=5m

$ kubectl wait --for=condition=Established \
    crd/securityprofiles.agents.kruise.io \
    crd/trafficpolicies.agents.kruise.io \
    crd/globaltrafficpolicies.agents.kruise.io \
    --timeout=60s

$ kubectl api-resources --api-group=agents.kruise.io
```

## Add a workload

Create an isolated namespace and enable sidecar injection:

```console
$ kubectl create namespace agentio-demo
$ kubectl label namespace agentio-demo istio-injection=enabled
```

Deploy the repository's curl sample:

```console
$ kubectl apply --namespace agentio-demo -f samples/curl/curl.yaml
$ kubectl rollout status deployment/curl \
    --namespace agentio-demo \
    --timeout=2m
```

## Verify sidecar injection

Wait for the sample Pod to become ready:

```console
$ kubectl wait pod \
    --namespace agentio-demo \
    --selector app=curl \
    --for=condition=Ready \
    --timeout=2m
```

Depending on the Kubernetes version and native-sidecar support, the injected proxy can appear as a regular container or as a restartable init container. Inspect both lists:

```console
$ kubectl get pod \
    --namespace agentio-demo \
    --selector app=curl \
    --output jsonpath='{range .items[0].spec.containers[*]}container={.name}{"\n"}{end}{range .items[0].spec.initContainers[*]}initContainer={.name} restartPolicy={.restartPolicy}{"\n"}{end}'
```

Confirm that the output contains the `curl` application and an injected `istio-proxy`. Agentio also labels the injected Pod with its proxy type:

```console
$ kubectl get pod \
    --namespace agentio-demo \
    --selector app=curl \
    --output jsonpath='{.items[0].metadata.labels.networking\.agents\.kruise\.io/proxy-type}{"\n"}'
ztunnel
```

Send a baseline request from the application container:

```console
$ kubectl exec deployment/curl \
    --namespace agentio-demo \
    --container curl -- \
    curl --fail --silent --show-error --head http://www.example.com
```

Export the workload interface used by the shared task pages:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-demo
$ export AGENTIO_WORKLOAD_LABEL=curl
$ export AGENTIO_WORKLOAD_CONTAINER=curl
```

## Route traffic through an egress gateway

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). You can create the gateway with either the Gateway API or the Agentio Helm chart.

## Apply a TrafficPolicy

After the egress route works, follow [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md).

## Clean up

First follow the cleanup sections in the shared `TrafficPolicy` and egress gateway tasks. Then delete the sample namespace created by this guide:

```console
$ kubectl delete namespace agentio-demo
```

Uninstalling Agentio is a separate operation because the chart owns the Agentio CRDs and uninstalling it removes custom resources stored under them.

## See also

- [Getting started](../getting-started.md)
- [Ambient mode](ambient-mode.md)
- [OpenKruise Agents integration](../integrations/openkruise-agents.md)
- [Agentio Helm values](../../manifests/charts/agentio/values.yaml)
