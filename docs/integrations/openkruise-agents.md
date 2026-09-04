# Integrate OpenKruise Agents

Use this integration when OpenKruise Agents creates a workload as a `Sandbox`. The Agentio watches the `Sandbox` and its controller-owned Pod, derives a stable sandbox identity, and attaches Agentio policy to that identity.

This integration changes the workload source; it is not a third Agentio data-plane profile. Install Agentio with either the ambient or sidecar profile required by your runtime distribution.

## Before you begin

You need:

- Agentio installed by following [Getting started](../getting-started.md);
- OpenKruise Agents and the `sandboxes.agents.kruise.io` CRD installed;
- a runtime integration that enrolls the Sandbox Pod in the selected Agentio data plane.

Verify the API and control plane:

```console
$ kubectl get crd sandboxes.agents.kruise.io
$ kubectl rollout status deployment/agentiod --namespace agentio-system --timeout=5m
```

## Understand the identity boundary

Agentio treats `Sandbox` as the policy subject and its backing Pod as the network endpoint and authenticated attester. The controller accepts the binding only when the Pod UID reported by the data plane matches the identity derived from the Sandbox, and the Sandbox is running with an initialized runtime.

For a non-pooled Sandbox, the fallback identity is `<namespace>--<name>`. When `agents.kruise.io/sandbox-id` is present, that label is the delivery identity. A pooled Sandbox is published as a policy subject only while it is claimed; ambiguous or stale bindings fail closed.

Do not copy a sandbox identity label onto an unrelated Pod. Labels are selection metadata, not proof that a Pod owns a Sandbox identity.

## Create a Sandbox

The exact runtime list is owned by the installed OpenKruise Agents distribution. The following example uses its `traffic-proxy` runtime contract; confirm that your distribution provides that runtime before applying it:

```console
$ kubectl create namespace agentio-agents-demo

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

Wait for the resource and its Pod:

```console
$ kubectl wait sandbox/agentio-sample --namespace agentio-agents-demo --for=condition=Ready --timeout=2m
$ kubectl wait pod --namespace agentio-agents-demo --selector app=agentio-agents-sample --for=condition=Ready --timeout=2m
$ kubectl get sandbox agentio-sample --namespace agentio-agents-demo --output yaml
```

If the Sandbox never becomes ready, inspect the OpenKruise Agents controller and runtime-distribution logs first. Agentio consumes the resulting Sandbox and Pod; it does not create or repair the external runtime integration.

## Continue with Agentio policy

Save the generated Pod name and export the interface used by the shared tasks:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-agents-demo
$ export AGENTIO_WORKLOAD_LABEL=agentio-agents-sample
$ export AGENTIO_WORKLOAD_CONTAINER=sandbox

$ AGENTIO_WORKLOAD_POD=$(kubectl get pod --namespace "$AGENTIO_DEMO_NAMESPACE" --selector "app=$AGENTIO_WORKLOAD_LABEL" --output jsonpath='{.items[0].metadata.name}')
$ test -n "$AGENTIO_WORKLOAD_POD"
```

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md), then [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md). Policy selectors use the Sandbox's effective labels; protected internal labels from an unrelated Pod are not allowed to replace Sandbox-owned identity.

## Clean up

Complete the cleanup sections in the shared tasks, then delete the Sandbox and namespace:

```console
$ kubectl delete sandbox agentio-sample --namespace agentio-agents-demo
$ kubectl delete namespace agentio-agents-demo
```

Do not remove the shared OpenKruise Agents installation or runtime configuration as part of this sample cleanup.

## See also

- [Getting started](../getting-started.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
