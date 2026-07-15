# AI Agent Guide (Agentio)

This file applies to the entire repository. A more specific `AGENTS.md` in a subdirectory takes precedence for that subtree, and explicit user prompts override this file.

## Core Rules

- Read related files, tests, and recent diffs before editing; treat the code as the source of truth.
- Agentio is an Istio derivative — avoid broad mechanical renames across upstream packages or generated code, and keep every change scoped and minimal.
- Do not add unrelated refactors to a focused change.
- Do not hand-edit generated files (`*.pb.go`, `*_vtproto.pb.go`, `*_json.gen.go`, CRD output, anything marked `DO NOT EDIT`); edit the source and regenerate.
- Do not commit, amend, rebase, push, publish, or open a PR unless explicitly requested; never use destructive Git commands to discard work without approval.
- Preserve user changes and unrelated untracked files; stage only explicit paths.
- Keep work inside this repository unless the user explicitly expands scope.
- Ask before a business or protocol decision that materially changes the requested scope.
- Do not claim a check passed unless it ran successfully in the current worktree; update focused tests when behavior changes.
- For read-only reviews, do not edit files; cite findings with exact paths and line numbers.

## Role

Act as a senior Go engineer specializing in Kubernetes networking, Envoy/xDS, Istio control-plane development, and traffic security for untrusted workloads.

## Project Overview

Agentio is a traffic security control system for agents, sandboxes, and other untrusted or compromise-prone workloads. It is a modified derivative of Istio that reuses Istio's control-plane, proxy, injection, and test infrastructure while adding Agentio-specific policy and workload configuration. See `README.md` for product context.

Repository map (Agentio-relevant paths):

- `pilot/cmd/pilot-discovery/` — control-plane entrypoint deployed as `agentiod`.
- `pilot/pkg/serviceregistry/kube/controller/agentio/` — Agentio controllers, policy translation, config sources, extension protobufs, and on-demand certificates.
- `pilot/pkg/networking/core/` — Envoy cluster, listener, and route generation; Agentio files retain the domain term `sandbox` where appropriate.
- `pkg/model/`, `pkg/workloadapi/security/` — shared xDS models and workload authorization types.
- `manifests/charts/agentio/` — Helm chart: control plane, sidecar injection, ambient mode, CRDs, gateways, and optional traffic extension.
- `tests/integration/agentio/` — KinD-based integration and E2E suite.
- `pilot/docker/Dockerfile.proxy_init` — lightweight init image that programs iptables/nftables rules.
- `tools/proto/` — protobuf generation, including Agentio extensions.
- `prow/`, `.github/workflows/` — CI/local KinD runners and release workflows.

## Tech Stack

- Go; the module path remains `istio.io/istio`.
- Kubernetes platform; Istio Pilot, KRT, Envoy xDS, gRPC, and protobuf.
- Policy APIs: `agents.kruise.io/v1alpha1` from `openkruise/agents-api`.
- Helm 3 deployment.
- Testing: Go unit tests, Istio's test framework, Ginkgo/Gomega-style integration tests, and KinD.
- Observability: Istio logging scopes and Prometheus metrics.

## Build & Environment

- `make <target>` runs inside the Istio build-tools container by default (`BUILD_WITH_CONTAINER=1`), so Docker and `make` are the only local prerequisites; CI runs the same targets directly inside `gcr.io/istio-testing/build-tools`.
- Common targets: `make build` (Go binaries), `make gen` (regenerate generated code), `make racetest` / `make test` (unit tests), `make binaries-test`, `make lint`. See the Makefile for the full list.
- `make test.e2e.agentio` runs on the host (`BUILD_WITH_CONTAINER=0`) because it drives KinD and local Docker.

## Architecture Invariants

### API and xDS Names Are Separate Contracts

- Kubernetes policy resources use `agents.kruise.io/v1alpha1`.
- Extension protobuf type URLs use `type.googleapis.com/kruise.networking.extensions.v1.*`.
- Keep `extensionPrefix` in `pilot/pkg/serviceregistry/kube/controller/agentio/extensions.go`, protobuf package names, generated type URLs, and tests aligned.
- `pkg/model/xds.go` defines the outer `WorkloadConfigType`; update it and its tests explicitly when the WCDS protocol name changes.
- Do not replace neutral API or protocol names with implementation-branded names without an explicit design decision.

### Preserve Intentional Upstream and Domain Naming

- Agentio is based on Istio; avoid broad mechanical renames across upstream packages or generated code.
- `sandbox` remains valid when it describes a workload, policy field, label, or Kubernetes/CRI sandbox concept. Rename only identifiers that refer to the old project/component name.
- Keep Agentio-specific behavior scoped to Agentio packages, the chart, or the integration suite unless a shared Istio change is required.

### Deployment Modes Must Remain Isolated

- Sidecar injection and ambient mode are independently configurable; changing one must not silently enable, disable, or leak state into the other.
- Local E2E scenarios use fresh KinD clusters so CNI and firewall state do not cross scenario boundaries.

### Release Boundaries

- The root `VERSION` file is Istio build metadata, not the Agentio product version.
- Agentio releases are driven by versioned release branches/tags, Chart metadata, and the Agentio release workflows.
- `pilot`, `proxy-init`, `proxy`, `ztunnel`, traffic extension, and CNI images do not share one build source or release cadence. Check the release workflow and chart values before changing image tags.

## Coding Conventions

### General Style

- Follow Effective Go and the surrounding Istio package style; format with `gofmt` and keep imports organized.
- Prefer small, purpose-specific packages over new catch-all `util`, `common`, or `helpers` packages.
- Keep comments and user-facing identifiers in English; preserve useful comments, rewriting only stale ones.

### Copyright and Attribution

- New Agentio Go files need the full Apache 2.0 header with `Copyright 2026 The Kruise Authors`.
- When modifying an Istio-derived file, keep its Istio header and add `Modifications Copyright 2026 The Kruise Authors` directly below the original copyright line.
- Use `./bin/fix_copyright_kruise.sh <base-ref>` and validate with `./bin/lint_copyright_kruise.sh <base-ref>`. Do not use `common/scripts/fix_copyright_banner.sh` — it applies the upstream Istio banner.
- Preserve `NOTICE`, `README.istio.md`, license files, and attribution text.

### Generated Code

- Edit the source `.proto` files under `pilot/pkg/serviceregistry/kube/controller/agentio/extensions/`, then run `./tools/proto/generate-agentio.sh`.
- Use broader generators such as `make gen` only when the changed source requires them; they are expensive and touch a large upstream surface.
- Review every generated diff and keep it limited to the intended change.

### Errors, Logging, and Concurrency

- Handle every error and wrap it with `%w` where callers may need classification.
- Follow the surrounding package's logging style; Agentio control-plane code uses an `istiolog.RegisterScope` scope — do not add a second logging framework to the same subsystem.
- Use structured log fields or formatted scope methods, not `fmt.Println`.
- Honor stop channels and context cancellation in controllers, retries, and long-running goroutines.
- Avoid `panic` except for unrecoverable startup or programmer errors that match the surrounding Istio convention.

### Shell and Workflow Changes

- Keep shell scripts compatible with Bash 3.2 unless the script explicitly declares a newer runtime requirement.
- Quote variables, fail closed on invalid booleans, and handle empty, whitespace, duplicate, and trailing-delimiter inputs.
- For workflow changes, preserve protected release boundaries and never expose credentials in command output.

## Commits and PRs

- Development happens on `release-*` branches, which hold the Agentio patch set on top of an upstream Istio release; keep history linear.
- Integrate upstream Istio by rebasing the Agentio patch set onto the new release — never with merge commits, which do not survive the rebase workflow. Squash feature branches to one logical patch so they replay cleanly on the next rebase.
- Match the existing history style (`area: short summary`; release-branch changes carry a `[release-*]` prefix).
- Keep each commit and PR focused on a single concern; do not mix unrelated changes.
- Do not add AI or tool attribution or co-authors to commits or PRs.
- Keep generated artifacts, release metadata, and chart image tags consistent with their source of truth.

## Testing and Validation

Run checks proportional to the change — narrowest relevant test first, expand only when the affected boundary requires it.

### Go Changes

For local iteration, run the narrowest affected packages (add `-race` for concurrency-sensitive changes):

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/agentio/...
go test ./pkg/model/... ./pkg/kube/krt/...
```

### Helm Chart Changes

```bash
helm lint manifests/charts/agentio
helm template agentio manifests/charts/agentio >/dev/null
helm template agentio manifests/charts/agentio --set ambient.enabled=true --set sidecarInjector.enabled=true >/dev/null
helm template agentio manifests/charts/agentio --set ambient.enabled=true --set sidecarInjector.enabled=true --set global.enableClusterTrustBundle=true >/dev/null
```

When changing a conditional feature, also render the exact value combination that enables it; a successful default render does not prove a disabled branch.

### Workflows and Shell

```bash
actionlint -color=false .github/workflows/*.yml
git diff --check
bash -n path/to/changed-script.sh
```

Run only the checks that correspond to files in scope.

### Agentio Local E2E

```bash
make test.e2e.agentio
```

- Selectors: `SCENARIO=sidecar-auto`, `TEST=TestName`.
- For prebuilt data-plane images, copy `tests/integration/agentio/testdata/local-values.yaml.example` to the ignored `local-values.yaml` beside it and fill in all required image groups.
- The runner creates/deletes KinD clusters and uses local Docker. Run it only when requested or when the change genuinely crosses the local E2E boundary.
