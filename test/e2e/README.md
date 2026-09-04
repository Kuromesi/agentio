# Kubernetes E2E framework

This nested Go module is the repository-owned Kubernetes E2E framework. Its
core packages are product-neutral and use ordinary `testing.T`, `t.Run`,
`t.Cleanup`, and `go test -run`. The reusable components cover Agentio
installation, namespaces, Helm releases, strict manifest plans, network
prefixes, the pinned Istio echo application, and retry-aware echo checks.

The framework never imports Istio Pilot, operator, security, istioctl, or the
Istio test framework. `go test . -run TestForbiddenDependencies` enforces that
boundary.

## Unit tests

Run all tests without a cluster:

```bash
make test
```

The live suites are opt-in and skip by default.

## Reusable test helpers

The helper surface follows the small, useful parts of Agentio's framework
without importing Istio's `TestContext` or `Environment`:

- `config.New(scope).YAML/Eval/File/EvalFile(...).ApplyOrFail(...)` renders and
  applies ordered manifest plans. Explicit plan deletion and final
  `ResourceScope` cleanup share the same UID/run-label ownership records.
- `echo.CallOptions.Check` is evaluated inside the call retry loop.
  `components/echo/check` provides `OK`, `NoError`, `Error`, `Status`, `And`,
  and workload-reachability checks; `Instance.CallOrFail` reports all attempts.
- `echo.Instance` owns named-port call options, Service IP, and ready-workload
  lookup. `network` owns host and arbitrary-prefix CIDR derivation.
- `components/agentio.Setup` installs the production
  `manifests/charts/agentio` chart once per suite. It pins immutable images,
  owns the chart CRDs and external Sandbox CRD through the suite ledger, and
  fails closed when a requested reusable release has a different fingerprint.
- `e2e.Context` bounds a helper operation by both its requested timeout and the
  enclosing Go test deadline.

Consumer suites should keep only product semantics such as policy propagation
or firewall assertions. Generic YAML, Kubernetes, network, or echo-call helpers
belong in their reusable package, not in an individual test file.

## Agentio product suites

The Agentio product tests are split into four per-domain suites, mirroring
Istio's `tests/integration` layout. Each suite is an independent Go package
with its own `TestMain` and setup graph, installs the production chart through
`components/agentio.Setup`, and uninstalls it on exit. The same suites run in
both sidecar and ambient profiles on separate clusters:

- `suites/trafficpolicy`: sandbox TrafficPolicy matrix (12 top-level tests
  with 50 scoped subscenarios plus one whole-test lifecycle scenario) and the
  control-plane config debug surface. The fixture contains `client`, `server`,
  `another-server`, and two `workload-target` Pods using the selected dataplane
  path. The matrix covers basic ingress and egress rules, global policy and
  priority, selector expressions, workload and service peers, TCP/UDP/ICMP
  protocol rules, policy interaction, Cartesian port/source cases, and
  selectorless Services with manual EndpointSlices. It preserves the policy
  documents and assertions from Agentio commit
  `4e6107d0444555a193b1a9224626a0e59d79b34c`.
- `suites/gateway`: egress gateway configuration, TLS termination and
  on-demand certificates, DFP routing, static ServiceEntries, ext-proc, and
  egress policies.
- `suites/securitypolicy`: SNI SecurityProfile and GlobalSecurityProfile
  lifecycle against dedicated SNI fixture namespaces.
- `suites/epe`: the Egress Policy Enforcer attribute, RBAC, metrics, and
  profile-priority contracts.

The shared product conventions (the `AGENTIO_E2E` gate, baseline ConfigMap,
scenario ledgers with contamination tracking, and profile-neutral echo
fixtures) live in `suites/internal/harness`. Each product fixture namespace is
enrolled with `agentio.kruise.io/dataplane-mode`; ordinary Echo workloads carry
only workload labels. In sidecar mode the namespace selector activates the
default ztunnel injection template, while ambient mode uses CNI redirection and
the node-level ztunnel. Every scenario owns its transient policies and endpoint
objects through a scoped ledger: successful scenarios clean up before the next
scenario, while a failed scenario retains its evidence and causes later
scenarios in the same suite to skip instead of running against contaminated
state.

All supplied suite images must be immutable digest references. The forward
proxy fixture uses a framework-owned Envoy digest by default; set
`AGENTIO_E2E_FORWARD_PROXY_IMAGE` only to override it. CI runs the four product
suites in four isolated scenarios: `sidecar-auto`, `sidecar-iptables`,
`ambient-auto`, and `ambient-iptables`. Suite setup verifies the requested
`FIREWALL_BACKEND` on the injected sidecar or ambient ztunnel Pod before any
product assertion runs.

Pull requests and master pushes use `agentio-e2e-presubmit.yml`. It builds the
repository-owned agentiod and EPE images plus the repository-owned ext-proc
test fixture once, transfers them to each matrix job as a same-run artifact,
and publishes them only to that job's KinD-local registry. CNI, proxy-init,
gateway, and ztunnel remain the immutable public images recorded in
`agentio.deps`, so presubmit needs no registry credentials. Release calls the
same product workflow with an immutable candidate BOM and promotes only the
digests that passed it.

A complete local run of all product suites is:

```bash
cd test/e2e
export AGENTIO_E2E_AGENTIOD_IMAGE='registry.example/agentiod@sha256:<64-hex-digest>'
export AGENTIO_E2E_CNI_IMAGE='registry.example/install-cni@sha256:<64-hex-digest>'
export AGENTIO_E2E_ZTUNNEL_IMAGE='registry.example/ztunnel@sha256:<64-hex-digest>'
export AGENTIO_E2E_PROXY_INIT_IMAGE='registry.example/proxy-init@sha256:<64-hex-digest>'
export AGENTIO_E2E_GATEWAY_IMAGE='registry.example/gateway@sha256:<64-hex-digest>'
export AGENTIO_E2E_EPE_IMAGE='registry.example/epe@sha256:<64-hex-digest>'
export AGENTIO_E2E_EXT_PROC_IMAGE='registry.example/ext-proc@sha256:<64-hex-digest>'
AGENTIO_E2E=1 go test -p 1 \
  ./suites/trafficpolicy ./suites/gateway ./suites/securitypolicy ./suites/epe \
  -v -count=1 \
  -agentio.enable-firewall-rules=true \
  -agentio.firewall-backend=auto \
  -agentio.agentiod-image="$AGENTIO_E2E_AGENTIOD_IMAGE" \
  -agentio.cni-image="$AGENTIO_E2E_CNI_IMAGE" \
  -agentio.ztunnel-image="$AGENTIO_E2E_ZTUNNEL_IMAGE" \
  -agentio.proxy-init-image="$AGENTIO_E2E_PROXY_INIT_IMAGE" \
  -agentio.gateway-image="$AGENTIO_E2E_GATEWAY_IMAGE" \
  -agentio.epe-image="$AGENTIO_E2E_EPE_IMAGE" \
  -agentio.ext-proc-image="$AGENTIO_E2E_EXT_PROC_IMAGE"
```

The command above defaults to `-agentio.profile=sidecar`. Run the same suites
against the ambient data plane in a separate fresh cluster:

```bash
AGENTIO_E2E=1 AGENTIO_E2E_PROFILE=ambient go test -p 1 \
  ./suites/trafficpolicy ./suites/gateway ./suites/securitypolicy ./suites/epe \
  -v -count=1 \
  [the same immutable image flags as above...]
```

`-p 1` is required for multi-suite runs: each suite is a separate test binary
and concurrent binaries would race on the cluster and the Helm release name.
A single suite can be run alone by naming just its package.

By default every suite creates and deletes its own Kind cluster. To share one
cluster across the suites — the same pattern Istio CI uses, where the CI
script owns the cluster and each suite only installs its control plane — create
the cluster first and borrow it:

```bash
kind create cluster --name dev-e2e
E2E_CLUSTER_NAME=dev-e2e E2E_CLUSTER_REUSE=true AGENTIO_E2E=1 go test -p 1 \
  ./suites/trafficpolicy ./suites/gateway ./suites/securitypolicy ./suites/epe \
  -v -count=1 [image flags as above...]
```

Each suite still installs and uninstalls its own chart release; the borrowed
cluster is never deleted. With `-e2e.lifecycle.retain=on-failure` or `always`,
a failed suite retains its release, and any later suite on the same cluster
fails closed because the release already exists — investigate and delete the
retained release before rerunning.

The gateway and securitypolicy suites need outbound DNS plus HTTP and HTTPS
access to `example.com` and `example.org`. Set
`-agentio.enable-firewall-rules=true` to exercise the full trafficpolicy
protocol matrix; otherwise the three UDP/ICMP scenarios skip explicitly. The
`-agentio.firewall-backend` value is `auto` or `iptables` and can also be set by
`AGENTIO_E2E_FIREWALL_BACKEND`. The corresponding boolean environment variable
is `AGENTIO_E2E_ENABLE_FIREWALL_RULES`.

The same framework cluster and retention flags described below apply. For
failure investigation, add `-e2e.lifecycle.retain=on-failure`; a passing run is
still cleaned, while a failing run keeps the exact owned cluster/resources and
prints reconnect and deletion commands. Set `AGENTIO_E2E_REUSE=true` only when
the existing Agentio installation has the exact manifest and image fingerprint
requested by the run; a mismatch fails closed without patching it.

The component defaults to Helm release `agentio` and the production chart in
this source tree. Override those only for an intentional integration setup with
`-agentio.release-name`, `-agentio.chart-path`,
`AGENTIO_E2E_RELEASE_NAME`, or `AGENTIO_E2E_CHART_PATH`.

This matrix covers the currently supported ordinary-Pod compatibility
projection. It does not claim coverage of a real Sandbox UID and structured
Workload-to-Sandbox binding; that remains a separate future scenario.

## New disposable Kind cluster

Install Docker, Kind, kubectl, and Helm, then run:

```bash
make test.integration.agentio.kube
```

The default creates a unique Kind cluster, writes artifacts below
`test/e2e/artifacts/<run-id>`, and removes resources and the owned cluster at
the end.

## Reuse a named Kind cluster

The named cluster must already exist. It is borrowed and is never deleted:

```bash
cd test/e2e
E2E_FRAMEWORK_SMOKE=1 go test ./suites/framework -v -count=1 \
  -e2e.cluster.name=dev-e2e \
  -e2e.cluster.reuse=true
```

If the name exists while reuse is false, setup fails without changing that
cluster.

## Existing kubeconfig context

An existing context is always borrowed. Retention controls only resources
owned by the current run:

```bash
cd test/e2e
E2E_FRAMEWORK_SMOKE=1 go test ./suites/framework -v -count=1 \
  -e2e.cluster.mode=existing \
  -e2e.cluster.kubeconfig=/absolute/path/to/kubeconfig \
  -e2e.cluster.context=my-context \
  -e2e.lifecycle.retain=on-failure
```

`KUBECONFIG` is used only when `-e2e.cluster.kubeconfig` and
`E2E_CLUSTER_KUBECONFIG` are unset.

## Retention and recovery

`-e2e.lifecycle.retain` accepts:

- `never`: delete exact-owned resources and an owned Kind cluster;
- `on-failure`: retain Kubernetes state after a failed run;
- `always`: retain Kubernetes state after every run.

Borrowed clusters are never deleted for any value. Local processes and
temporary kubeconfigs are always closed or removed.

For `on-failure` and `always`, component-level Kubernetes cleanup is deferred
until the Suite knows the final result. This avoids `testing.T` cleanup deleting
the evidence before `TestMain` can apply the retention policy. A successful
`on-failure` run is still cleaned normally by the Suite ledger.

Every run writes `environment.json` with cluster identity, ownership, resource
GVR/name/namespace/UID, run label, manifest hash, component fingerprints,
retention policy, and final status. Cleanup re-reads each object and requires
both the recorded UID and run label before issuing a UID-preconditioned delete.
A replaced or foreign object is left untouched.

For a retained owned Kind cluster the Suite prints both a reconnect command
and the exact manual deletion command:

```bash
KUBECONFIG=/path/from/output kubectl --context kind-cluster-name get pods -A
kind delete cluster --name cluster-name
```

## Configuration

Configuration precedence is:

```text
framework defaults < suite defaults < strict YAML < E2E_* environment < CLI
```

Use `-e2e.config=/path/config.yaml` for the framework-only strict schema.
Unknown fields and invalid combinations fail before cluster mutation. Product
suites own separate flag and file namespaces.

The core flags are:

```text
-e2e.config
-e2e.artifacts.dir
-e2e.cluster.mode=kind|existing
-e2e.cluster.name
-e2e.cluster.kubeconfig
-e2e.cluster.context
-e2e.cluster.reuse
-e2e.cluster.kind.node-image
-e2e.cluster.kind.config
-e2e.lifecycle.retain=never|on-failure|always
-e2e.diagnostics.full-on-failure
-e2e.diagnostics.max-full-dumps
```

Command arguments, output, credential paths, and configured secrets are
redacted in artifacts. Failure diagnostics always keep the original failure;
collector failures are recorded separately, and full dumps are capped by
`max-full-dumps`.

## Live-test prerequisites

New Kind runs require Docker and Kind. The framework smoke test additionally
expects the pinned echo image to be reachable; Agentio runs require the seven
immutable images above. Existing-context runs do not require Docker or Kind,
but the selected Kubernetes context and image registry must be reachable.

The unit, vet, race, and dependency-boundary gates do not require a cluster.
Do not treat a skipped live suite or a failed prerequisite check as a passing
Kubernetes E2E run.
