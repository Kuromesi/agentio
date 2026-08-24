# Substrate PREROUTING-only CNI Implementation Plan

> **For agentic workers:** Execute inline in this worktree with test-driven development. Do not delegate because the user requested a direct implementation in the existing PoC branch.

**Goal:** Add an explicit CNI mode that captures selected Actor traffic in `PREROUTING` without intercepting Worker-local `OUTPUT` traffic.

**Architecture:** A shared annotation value is parsed independently by the Ambient node agent and Sidecar CNI Redirect builder. Ambient rule builders use a Pod override boolean to emit only explicit reroute selectors. Sidecar CNI passes the boolean through the common iptables configuration and both sidecar backends skip OUTPUT setup while preserving virtual-interface PREROUTING rules.

**Tech Stack:** Go, Kubernetes Pod annotations, iptables, nftables, Helm injection templates, Go golden tests.

## Global Constraints

- Annotation: `agentio.io/interception-mode: prerouting-only`.
- Default behavior must be byte-for-byte compatible when the annotation is absent.
- No Substrate or ztunnel protocol changes.
- Both iptables and native nftables must be covered.
- New comments and identifiers remain in English.

---

### Task 1: Annotation model and parsing

**Files:**

- Modify: `cni/pkg/config/config.go`
- Modify: `cni/pkg/nodeagent/net.go`
- Modify: `cni/pkg/nodeagent/net_test.go`
- Modify: `cni/pkg/plugin/sidecar_redirect.go`
- Modify: `cni/pkg/plugin/sidecar_redirect_test.go`

**Interfaces:**

- Produce `config.InterceptionModeAnnotation`, `config.InterceptionModePreroutingOnly`, and `PodLevelOverrides.PreroutingOnly`.
- Produce `Redirect.preroutingOnly` for Sidecar rule programming.

- [ ] Add failing parsing tests for Ambient and Sidecar.
- [ ] Run the focused tests and confirm failure because the mode is not implemented.
- [ ] Add constants, parsing and validation.
- [ ] Run focused parsing tests and confirm success.

### Task 2: Ambient iptables and nftables behavior

**Files:**

- Modify: `cni/pkg/iptables/iptables.go`
- Modify: `cni/pkg/iptables/iptables_test.go`
- Modify: `cni/pkg/nftables/nftables.go`
- Modify: `cni/pkg/nftables/nftables_test.go`

**Interfaces:**

- Consume `PodLevelOverrides.PreroutingOnly`.
- Preserve explicit source CIDR, bridge prefix and virtual-interface reroutes.

- [ ] Add failing tests requiring source-CIDR PREROUTING redirect and forbidding OUTPUT and ordinary inbound redirects.
- [ ] Run both backend tests and confirm failure on existing OUTPUT rules.
- [ ] Guard OUTPUT, DNS OUTPUT, mark restoration and ordinary inbound catch-all generation.
- [ ] Run both backend tests and confirm success.

### Task 3: Sidecar iptables and nftables behavior

**Files:**

- Modify: `tools/common/config/config.go`
- Modify: `cni/pkg/plugin/sidecar_iptables_linux.go`
- Modify: `cni/pkg/plugin/sidecar_nftables_linux.go`
- Modify: `tools/istio-iptables/pkg/capture/run.go`
- Modify: `tools/istio-iptables/pkg/capture/run_test.go`
- Modify: `tools/istio-nftables/pkg/capture/run.go`
- Modify: `tools/istio-nftables/pkg/capture/run_test.go`

**Interfaces:**

- Produce `config.Config.PreroutingOnly`.
- Consume `Redirect.preroutingOnly` in both Sidecar CNI backends.

- [ ] Add failing tests requiring virtual-interface PREROUTING redirect and forbidding OUTPUT hooks.
- [ ] Run both sidecar backend tests and confirm failure.
- [ ] Add a focused PREROUTING-only branch after shared redirect-chain and inbound setup.
- [ ] Run both backend tests and confirm success without updating unrelated goldens.

### Task 4: Chart and documentation

**Files:**

- Modify: `manifests/charts/agentio/files/ztunnel-injection-template.yaml`
- Modify: `cni/README.md`
- Modify: `docs/tasks/manage-substrate-egress-with-ambient-ztunnel.zh-CN.md`

**Interfaces:**

- Preserve `agentio.io/interception-mode` on injected Pods.
- Document that current Microsandbox prefers source CIDR over `ateom0`.

- [ ] Add the annotation to injection metadata and document valid behavior.
- [ ] Render the chart with Sidecar and Ambient enabled.

### Task 5: Verification and delivery

**Files:** All modified files.

- [ ] Run focused CNI, iptables and nftables Go tests.
- [ ] Run Helm lint and required render combinations.
- [ ] Run `gofmt`, `git diff --check`, and inspect the final diff.
- [ ] Commit only the explicit feature and documentation paths.
- [ ] Push `codex/actor-context-poc` to its configured origin.
