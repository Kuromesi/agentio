# Substrate PREROUTING-only CNI Implementation Plan

> **For agentic workers:** Execute inline in this worktree with test-driven development. Do not delegate because the user requested a direct implementation in the existing PoC branch.

**Goal:** Add an explicit CNI mode that captures selected Actor traffic in `PREROUTING` without intercepting Worker-local `OUTPUT` traffic.

**Architecture:** The Ambient node agent parses a Pod annotation into an in-pod override. The Ambient iptables and nftables rule builders use that override to emit only explicit Actor reroute selectors in `PREROUTING`.

**Tech Stack:** Go, Kubernetes Pod annotations, iptables, nftables, Go tests.

## Global Constraints

- Annotation: `agentio.io/interception-mode: prerouting-only`.
- Default behavior must be byte-for-byte compatible when the annotation is absent.
- No Substrate or ztunnel protocol changes.
- Both Ambient iptables and native nftables must be covered.
- Sidecar CNI is out of scope.
- New comments and identifiers remain in English.

---

### Task 1: Annotation model and parsing

**Files:**

- Modify: `cni/pkg/config/config.go`
- Modify: `cni/pkg/nodeagent/net.go`
- Modify: `cni/pkg/nodeagent/net_test.go`

**Interfaces:**

- Produce `config.InterceptionModeAnnotation`, `config.InterceptionModePreroutingOnly`, and `PodLevelOverrides.PreroutingOnly`.

- [x] Add a failing parsing test for Ambient.
- [x] Run the focused tests and confirm failure because the mode is not implemented.
- [x] Add constants, parsing and validation.
- [x] Run focused parsing tests and confirm success.

### Task 2: Ambient iptables and nftables behavior

**Files:**

- Modify: `cni/pkg/iptables/iptables.go`
- Modify: `cni/pkg/iptables/iptables_test.go`
- Modify: `cni/pkg/nftables/nftables.go`
- Modify: `cni/pkg/nftables/nftables_test.go`

**Interfaces:**

- Consume `PodLevelOverrides.PreroutingOnly`.
- Preserve explicit source CIDR, bridge prefix and virtual-interface reroutes.

- [x] Add failing tests requiring source-CIDR PREROUTING redirect and forbidding OUTPUT and ordinary inbound redirects.
- [x] Run both backend tests and confirm failure on existing OUTPUT rules.
- [x] Guard OUTPUT, DNS OUTPUT, mark restoration and ordinary inbound catch-all generation.
- [x] Run both backend tests and confirm success.

### Task 3: Documentation

**Files:**

- Modify: `docs/tasks/manage-substrate-egress-with-ambient-ztunnel.zh-CN.md`

**Interfaces:**

- Document that current Microsandbox prefers source CIDR over `ateom0`.

- [x] Document the annotation and valid behavior.

### Task 4: Verification and delivery

**Files:** All modified files.

- [x] Run focused Ambient CNI, iptables and nftables Go tests.
- [ ] Run `gofmt`, `git diff --check`, and inspect the final diff.
- [ ] Commit only the explicit feature and documentation paths.
- [ ] Push `codex/actor-context-poc` to its configured origin.
