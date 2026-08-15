# Integrate OpenKruise Agents

Use this integration when OpenKruise Agents creates your workloads as `Sandbox` or `SandboxSet` resources. The workload declares the `traffic-proxy` runtime, and the Agents controller applies an externally managed Agentio-compatible injection template.

This is a sidecar workload integration. It is not a third Agentio data plane mode.

## Before you begin

You need:

- Agentio installed with the control plane required by your traffic-proxy distribution.
- OpenKruise Agents installed in the cluster.
- The `Sandbox` and `SandboxSet` APIs.
- An Agents distribution that provides an Agentio-compatible `traffic-proxy` injection template.
- The namespace where the Agents controller reads its injection configuration.

Verify the APIs:

```console
$ kubectl get crd \
    sandboxes.agents.kruise.io \
    sandboxsets.agents.kruise.io
```

Set the actual Agents controller namespace for your installation. The upstream controller uses its Pod namespace and falls back to `sandbox-system` when that value is not available:

```console
$ export AGENTS_CONTROLLER_NAMESPACE=sandbox-system
```

Confirm that the external injection ConfigMap and its non-empty `traffic-proxy` key exist. This command reports only whether the key is configured; it does not print the template:

```console
$ kubectl get configmap sandbox-injection-config \
    --namespace "$AGENTS_CONTROLLER_NAMESPACE" \
    --output go-template='{{if index .data "traffic-proxy"}}traffic-proxy key: configured{{else}}traffic-proxy key: missing{{end}}{{"\n"}}'
traffic-proxy key: configured
```

The Agents distributor owns this ConfigMap entry, including proxy images, init containers, containers, labels, annotations, volumes, and security settings. This guide does not create or copy the JSON template. Stop here and contact the distributor if the ConfigMap or key is missing.

## Understand the injection flow

The stable user-facing contract is the runtime declaration:

```yaml
spec:
  runtimes:
  - name: traffic-proxy
```

When the Agents controller creates the Pod, it reads `data["traffic-proxy"]` from `ConfigMap/sandbox-injection-config` in its own namespace and applies that template to the Pod.

Create a separate workload namespace. Do not also enable Agentio's admission-based sidecar injection on this namespace unless your Agents distribution explicitly requires both mechanisms:

```console
$ kubectl create namespace agentio-agents-demo
```

## Enable traffic-proxy for a Sandbox

Use a `Sandbox` for one independently managed workload:

```console
$ kubectl apply --namespace agentio-agents-demo -f - <<'EOF'
apiVersion: agents.kruise.io/v1alpha1
kind: Sandbox
metadata:
  name: agentio-sample
spec:
  runtimes:
  - name: traffic-proxy
  template:
    metadata:
      labels:
        app: agentio-agents-sample
    spec:
      containers:
      - name: sandbox
        image: docker.io/curlimages/curl:8.16.0
        command: ["/bin/sleep", "infinity"]
EOF
```

Continue with [Verify the injected Pod](#verify-the-injected-pod).

## Enable traffic-proxy for a SandboxSet

Use a `SandboxSet` when the controller should maintain a pool of equivalent workloads:

```console
$ kubectl apply --namespace agentio-agents-demo -f - <<'EOF'
apiVersion: agents.kruise.io/v1alpha1
kind: SandboxSet
metadata:
  name: agentio-sample
spec:
  replicas: 1
  runtimes:
  - name: traffic-proxy
  template:
    metadata:
      labels:
        app: agentio-agents-sample
    spec:
      containers:
      - name: sandbox
        image: docker.io/curlimages/curl:8.16.0
        command: ["/bin/sleep", "infinity"]
EOF
```

Choose either the `Sandbox` or the `SandboxSet` example for this evaluation. Do not create both examples with the same name.

## Verify the injected Pod

First verify that the chosen resource declares the runtime. Run the command that matches the resource you created:

```console
$ kubectl get sandbox agentio-sample \
    --namespace agentio-agents-demo \
    --output jsonpath='{.spec.runtimes[*].name}{"\n"}'
traffic-proxy

$ kubectl get sandboxset agentio-sample \
    --namespace agentio-agents-demo \
    --output jsonpath='{.spec.runtimes[*].name}{"\n"}'
traffic-proxy
```

Wait for the generated Pod, then inspect the init-container and container names:

```console
$ kubectl wait pod \
    --namespace agentio-agents-demo \
    --selector app=agentio-agents-sample \
    --for=condition=Ready \
    --timeout=2m

$ kubectl get pod \
    --namespace agentio-agents-demo \
    --selector app=agentio-agents-sample \
    --output jsonpath='{.items[0].spec.initContainers[*].name}{"\n"}{.items[0].spec.containers[*].name}{"\n"}'
```

Compare the result with the `traffic-proxy` template supplied by your Agents distribution. This guide does not hard-code the proxy container name because the external template owns it.

Send a baseline request from the application container:

```console
$ AGENTIO_WORKLOAD_POD=$(kubectl get pod \
    --namespace agentio-agents-demo \
    --selector app=agentio-agents-sample \
    --output jsonpath='{.items[0].metadata.name}')

$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace agentio-agents-demo \
    --container sandbox -- \
    curl --fail --silent --show-error --head http://www.example.com
```

Export the workload interface used by the shared task pages:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-agents-demo
$ export AGENTIO_WORKLOAD_LABEL=agentio-agents-sample
$ export AGENTIO_WORKLOAD_CONTAINER=sandbox
```

## Route traffic through an egress gateway

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). Both the Gateway API waypoint and Helm-managed gateway methods use the same workload interface.

## Apply a TrafficPolicy

After the egress route works, follow [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md). The policy selects the stable `app: agentio-agents-sample` label from the Pod template.

## Clean up

First follow the cleanup sections in the shared `TrafficPolicy` and egress gateway tasks. Then delete the sample resource that you created:

```console
$ kubectl delete sandbox agentio-sample --namespace agentio-agents-demo
```

Or, for the `SandboxSet` example:

```console
$ kubectl delete sandboxset agentio-sample --namespace agentio-agents-demo
```

After the generated Pod is gone, delete the sample namespace:

```console
$ kubectl delete namespace agentio-agents-demo
```

Do not delete `ConfigMap/sandbox-injection-config` or the OpenKruise Agents installation as part of this sample cleanup. They are external shared dependencies.

## See also

- [Getting started](../getting-started.md)
- [Sidecar mode](../getting-started/sidecar-mode.md)
- [Actor identity over Worker mTLS PoC](actor-identity-worker-mtls-poc.md)
- [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
