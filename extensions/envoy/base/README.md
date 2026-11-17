# Agentio Envoy base image

This directory maintains a small Envoy patch for legacy external processors that read `filter_state['downstream_peer'].name` and `filter_state['downstream_peer'].namespace`.

`versions.env` pins the Envoy source, build image, and runtime image. The final base image replaces only `/usr/local/bin/envoy` in the pinned runtime image. It does not contain gateway-agent or Rust dynamic modules.

## Compatibility interface

The patch registers the `agentio.legacy_downstream_peer` filter-state object factory in Envoy's existing set-filter-state implementation. Its input is `name` followed by one newline and `namespace`. Both fields must be nonempty; extra newlines are rejected. Kubernetes workload names and namespaces cannot contain newlines.

The object exposes only the CEL string fields `name` and `namespace`. Unknown fields are absent. The factory does not restore Istio peer discovery or read client headers.

The internal control plane must create this object from the trusted canonical workload identity before the business ext_proc filter runs. Installing the image alone does not create `downstream_peer`. `sandbox.labels` remains a separate filter-state entry with its existing encoding and label filtering.

The factory's C++ tests are included in the patch at `//test/extensions/filters/common/set_filter_state:filter_config_test`. They cover field access, unknown fields, malformed input, and the absence of upstream sharing by default.

## Build workflow

`.github/workflows/envoy-image.yml` submits native amd64 and arm64 Kubernetes Jobs to a dedicated ACK cluster. Each Job uses a private Docker daemon sidecar; deleting the Job stops its compiler containers. No host Docker socket or self-hosted GitHub runner is used.

The native jobs apply the patch to the pinned Envoy source, run its C++ tests, and build an optimized Envoy binary inside the pinned build image. Each job packages the binary in the pinned runtime image, checks its architecture and version, and validates `smoke.yaml` to confirm that the custom factory is registered. Both jobs must succeed before publishing merges their immutable digests. Publishing also checks both source labels and the exact `linux/amd64`, `linux/arm64` platform set.

The destination is `docker.io/kuromesi/agentio-envoy`. Candidate tags include the Envoy version, Agentio source revision, Actions run ID, and attempt. The final immutable reference is written to the workflow summary and the `envoy-image` artifact. Internal gateway builds consume it through the existing `ENVOY_IMAGE` Docker build argument.

### ACK setup

Use a dedicated ACK cluster with Kubernetes 1.29 or later, containerd, Flannel, and the CSI disk add-ons. The Job uses Kubernetes native sidecars and a privileged Docker daemon. It must run on ECS worker nodes; ACS virtual nodes need separate privileged-container support and are not used here.

Prepare one native amd64 node pool and one native arm64 node pool in Hong Kong, each with 32 vCPUs and 128 GiB of RAM per node. Label both pools `agentio-build=true`. Give worker nodes outbound connectivity to GitHub, Bazel dependency sources, Docker Hub, and Alpine package repositories. An autoscaling pool can use a minimum of zero and maximum of one; keep a small system pool available for cluster services and node autoscaling.

Apply `ack-build.yaml` to create the namespace, workflow service account, namespace-scoped permissions, and one 500 GiB cache PVC per architecture. Place a Docker config with push permission for the destination in Secret `envoy-registry`, key `config.json`, in namespace `envoy-build`. Do not commit the Docker config.

Create the GitHub deployment environment `envoy-build` in `Kuromesi/agentio`. Set its `ENVOY_BUILD_KUBECONFIG` secret to a kubeconfig using a time-limited token for service account `envoy-build/envoy-workflow`. The account can submit and inspect Jobs only in this namespace. Refresh the token before each build campaign; do not upload an administrator kubeconfig. Restrict environment deployment branches and tags to `envoy-legacy-extproc` and trusted `envoy-base-*` tags.

### Triggering

Pull requests touching this directory run orchestration tests without cluster credentials. Ordinary branch pushes do not start a paid build. After reviewing and pushing the source commit, explicitly push a tag to build that commit:

```bash
git tag envoy-base-review-1 <reviewed-commit>
git push origin envoy-base-review-1
```

The workflow also supports `workflow_dispatch` on `envoy-legacy-extproc`. GitHub requires the workflow to exist on the repository's default branch before enabling that event; until then, use the tag trigger. No default-branch change is required for tag-triggered builds.

### Logs, cancellation, and costs

Native compilation is limited to 19800 seconds. The ACK Job deadline remains effective if the GitHub runner disappears. On success, failure, or cancellation, the runner deletes its Job and daemon. Completed build logs are uploaded to Actions; while compiling, inspect the Job's `build` container logs in ACK.

Generated checkouts, Docker layers, binaries, and Bazel caches reside on the per-architecture PVCs mounted at `/disk1`. Builds take a per-volume lock. Jobs are not retried automatically. Keep the PVCs across retries, then delete them when the build campaign ends: retaining cache disks, an idle ACK cluster, or running worker nodes continues to incur charges. Infrastructure creation and release are separate from this workflow. Remove the temporary GitHub access secret when releasing the cluster.

## Local checks

```bash
python3 -m unittest discover -s extensions/envoy/base -p '*_test.py' -v
bash -n extensions/envoy/base/build.sh
bash -n extensions/envoy/base/container-build.sh
bash -n extensions/envoy/base/publish.sh
actionlint .github/workflows/envoy-image.yml
```

The local tests exercise orchestration with fake cloud and Docker commands. They do not compile Envoy or prove runtime compatibility. End-to-end ext_proc attribute tests and Rust dynamic-module compatibility must run against the resulting images before an internal gateway consumes them.
