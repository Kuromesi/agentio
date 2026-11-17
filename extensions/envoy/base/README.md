# Agentio Envoy base image

This directory maintains a small Envoy patch for legacy external processors that read `filter_state['downstream_peer'].name` and `filter_state['downstream_peer'].namespace`.

`versions.env` pins the Envoy source, build image, and runtime image. The final base image replaces only `/usr/local/bin/envoy` in the pinned runtime image. It does not contain gateway-agent or Rust dynamic modules.

## Compatibility interface

The patch registers the `agentio.legacy_downstream_peer` filter-state object factory in Envoy's existing set-filter-state implementation. Its input is `name` followed by one newline and `namespace`. Both fields must be nonempty; extra newlines are rejected. Kubernetes workload names and namespaces cannot contain newlines.

The object exposes only the CEL string fields `name` and `namespace`. Unknown fields are absent. The factory does not restore Istio peer discovery or read client headers.

The internal control plane must create this object from the trusted canonical workload identity before the business ext_proc filter runs. Installing the image alone does not create `downstream_peer`. `sandbox.labels` remains a separate filter-state entry with its existing encoding and label filtering.

The factory's C++ tests are included in the patch at `//test/extensions/filters/common/set_filter_state:filter_config_test`. They cover field access, unknown fields, malformed input, and the absence of upstream sharing by default.

## Build workflow

`.github/workflows/envoy-image.yml` orchestrates two existing native ECS builders through Cloud Assistant. GitHub-hosted runners hold temporary OIDC credentials; the ECS instances hold the registry login. The workflow does not create ECS instances or register self-hosted GitHub runners.

The native jobs apply the patch to the pinned Envoy source, run its C++ tests, and build an optimized Envoy binary inside the pinned build image. Each job packages the binary in the pinned runtime image, checks its architecture and version, and validates `smoke.yaml` to confirm that the custom factory is registered. Both jobs must succeed before the publish job merges their immutable digests. Publishing also checks both source labels and the exact `linux/amd64`, `linux/arm64` platform set.

The destination is `registry-cn-hangzhou.ack.aliyuncs.com/dev/agentio-envoy`. Candidate tags include the Envoy version, Agentio source revision, Actions run ID, and attempt. The final immutable reference is written to the workflow summary and the `envoy-image` artifact. Internal gateway builds consume it through the existing `ENVOY_IMAGE` Docker build argument.

### One-time setup

Prepare one amd64 ECS and one arm64 ECS in Hong Kong, each with 32 vCPUs, 128 GiB of RAM, and a 500 GiB data disk mounted at `/disk1`. Install Git, Python 3, `flock`, Docker with Buildx, and a current Cloud Assistant agent. Allow outbound access to GitHub, Bazel dependency sources, Docker Hub, and the destination registry. GitHub does not require inbound SSH access.

Log Docker into the destination registry on both instances using a credential permitted to push `dev/agentio-envoy`. Provisioning must create the repository if it does not already exist. Do not place the registry credential in the repository or Cloud Assistant command content.

Create the GitHub deployment environment `envoy-build` in `Kuromesi/agentio` with these variables:

| Variable | Value |
| --- | --- |
| `ENVOY_BUILD_ECS_AMD64` | Native amd64 instance ID |
| `ENVOY_BUILD_ECS_ARM64` | Native arm64 instance ID |
| `ENVOY_BUILD_OIDC_PROVIDER` | Alibaba Cloud GitHub OIDC provider ARN |
| `ENVOY_BUILD_ROLE` | Cloud Assistant build role ARN |

Configure the provider for `https://token.actions.githubusercontent.com` with audience `sts.aliyuncs.com`. Restrict the role trust to subject `repo:Kuromesi/agentio:environment:envoy-build`, and restrict environment deployment branches and tags to `envoy-legacy-extproc` and trusted `envoy-base-*` tags. Set the role's `MaxSessionDuration` to at least 21600 seconds. Grant the role command execution and cancellation on the two dedicated builders, plus the invocation-result queries needed by the workflow; it does not need permission to create or delete ECS instances.

### Triggering

Pull requests touching this directory run the local orchestration tests without cloud credentials. Ordinary branch pushes do not start a paid build. After reviewing and pushing the source commit, explicitly push a tag to build that commit:

```bash
git tag envoy-base-review-1 <reviewed-commit>
git push origin envoy-base-review-1
```

The workflow also supports `workflow_dispatch` on `envoy-legacy-extproc`. GitHub requires the workflow to exist on the repository's default branch before enabling that event; until then, use the tag trigger. No default-branch change is required for tag-triggered builds.

### Logs, cancellation, and limits

Full logs remain at `/disk1/agentio-envoy/logs/<candidate>-<phase>-<architecture>.log`; the final 16000 bytes are returned to Actions. Native compilation is limited to 19800 seconds so the six-hour GitHub job retains time for cleanup. On cancellation or failure, the orchestration stops an active invocation and separately removes only that candidate's build container. The Cloud Assistant execution timeout remains in effect if the GitHub runner disappears.

Generated source checkouts and outputs live under `/disk1/agentio-envoy/runs/<Agentio revision>`. The Docker build container reuses Bazel caches under `/disk1/agentio-envoy/cache`. Builds take a per-instance lock. Infrastructure provisioning and release are separate from this workflow; an idle running ECS continues to incur charges.

## Local checks

```bash
python3 -m unittest discover -s extensions/envoy/base -p '*_test.py' -v
bash -n extensions/envoy/base/build.sh
bash -n extensions/envoy/base/container-build.sh
bash -n extensions/envoy/base/publish.sh
actionlint .github/workflows/envoy-image.yml
```

The local tests exercise orchestration with fake cloud and Docker commands. They do not compile Envoy or prove runtime compatibility. End-to-end ext_proc attribute tests and Rust dynamic-module compatibility must run against the resulting images before an internal gateway consumes them.
