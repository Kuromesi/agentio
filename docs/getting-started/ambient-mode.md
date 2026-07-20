# Get started with ambient mode

This guide installs Agentio's node-level data plane, enrolls a sample workload without injecting a proxy container, and prepares the workload for the shared egress gateway and `TrafficPolicy` tasks.

## Before you begin

You need:

- A Kubernetes cluster that you can administer.
- `kubectl` configured for that cluster.
- Helm 3.
- A local clone of this repository.
- Access to the container images configured in [`manifests/charts/agentio/values.yaml`](../../manifests/charts/agentio/values.yaml).

Run the commands in this guide from the repository root.

Ambient mode installs CNI and ztunnel DaemonSets on cluster nodes. These components use host paths and elevated network permissions to capture workload traffic. Evaluate ambient mode in an isolated cluster or namespace, review the rendered manifests, and follow your cluster's node-change procedures before enabling it in production.

## Install Agentio in ambient mode

Create an explicit pure-ambient values file:

```console
$ cat >/tmp/agentio-ambient-values.yaml <<'EOF'
sidecarInjector:
  enabled: false
ambient:
  enabled: true
EOF
```

Install Agentio from this repository:

```console
$ helm upgrade --install agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --values /tmp/agentio-ambient-values.yaml \
    --wait \
    --timeout 5m
```

Some default Agentio images use `docker.io/openkruise` and mutable `latest` tags, while the ambient CNI has a separate image value. Review every image value and override it when your environment uses a private registry or pinned release images.

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
```

## Verify the CNI and ztunnel

Wait for both node-level components to be ready:

```console
$ kubectl rollout status daemonset/agentio-cni-node \
    --namespace agentio-system \
    --timeout=5m

$ kubectl rollout status daemonset/ztunnel \
    --namespace agentio-system \
    --timeout=5m
```

## Add a workload to ambient mode

Create a dedicated evaluation namespace and enroll it in ambient mode:

```console
$ kubectl create namespace agentio-demo-ambient
$ kubectl label namespace agentio-demo-ambient istio.io/dataplane-mode=ambient
```

Deploy the repository's curl sample:

```console
$ kubectl apply --namespace agentio-demo-ambient -f samples/curl/curl.yaml
$ kubectl rollout status deployment/curl \
    --namespace agentio-demo-ambient \
    --timeout=2m
```

## Verify workload enrollment

The sample Pod becomes ready with only its application container:

```console
$ kubectl get pods --namespace agentio-demo-ambient
NAME                    READY   STATUS    RESTARTS   AGE
curl-xxxxxxxxxx-xxxxx   1/1     Running   0          30s

$ kubectl get pod \
    --namespace agentio-demo-ambient \
    --selector app=curl \
    --output jsonpath='{.items[0].spec.containers[*].name}{"\n"}'
curl
```

Confirm that the CNI marked the Pod as redirected to the ambient data plane:

```console
$ kubectl get pod \
    --namespace agentio-demo-ambient \
    --selector app=curl \
    --output jsonpath='{.items[0].metadata.annotations.ambient\.istio\.io/redirection}{"\n"}'
enabled
```

Send a baseline request from the workload:

```console
$ kubectl exec deployment/curl \
    --namespace agentio-demo-ambient \
    --container curl -- \
    curl --fail --silent --show-error --head http://www.example.com
```

Export the workload interface used by the shared task pages:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-demo-ambient
$ export AGENTIO_WORKLOAD_LABEL=curl
$ export AGENTIO_WORKLOAD_CONTAINER=curl
```

## Route traffic through an egress gateway

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). Both gateway creation methods support ambient-enrolled workloads.

## Apply a TrafficPolicy

After the egress route works, follow [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md). The shared task verifies policy behavior with real requests rather than sidecar-specific inspection.

## Clean up

First follow the cleanup sections in the shared `TrafficPolicy` and egress gateway tasks. Then delete the enrolled sample workload before disabling the node-level data plane:

```console
$ kubectl delete namespace agentio-demo-ambient
```

Remove the ambient DaemonSets from the Agentio release:

```console
$ cat >/tmp/agentio-disable-ambient-values.yaml <<'EOF'
ambient:
  enabled: false
EOF

$ helm upgrade agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --values /tmp/agentio-disable-ambient-values.yaml \
    --wait \
    --timeout 5m
```

Confirm that the `agentio-cni-node` and `ztunnel` DaemonSets are gone. If your Kubernetes distribution requires additional cleanup after removing a CNI component, follow its node cleanup procedure before reusing the nodes.

Uninstalling Agentio is a separate operation because the chart owns the Agentio CRDs and uninstalling it removes custom resources stored under them.

## See also

- [Getting started](../getting-started.md)
- [Sidecar mode](sidecar-mode.md)
- [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [Agentio Helm values](../../manifests/charts/agentio/values.yaml)
