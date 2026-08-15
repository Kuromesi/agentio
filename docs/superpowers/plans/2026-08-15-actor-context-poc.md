# Actor Context over Worker mTLS PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep ztunnel's Worker Pod certificate as the mTLS transport identity while carrying the currently assigned single Actor identity and generation on each HBONE CONNECT request.

**Architecture:** Substrate represents an active Actor assignment by labels on the Worker Pod. Agentiod derives a per-proxy `ActorContext` from the current ambient workload and embeds it in the existing WCDS `WorkloadConfig`. Ztunnel consumes that context, selects the token file whose key equals the Actor UID, and writes Actor identity, generation, labels, and token into trusted HBONE headers; the gateway relays those values into filter state for EPE.

**Tech Stack:** Go, Kubernetes ambient workload index, Envoy xDS/WCDS, protobuf, Rust, ztunnel HBONE, Agentio EPE.

## Global Constraints

- A Worker runs at most one Actor at a time; the Actor may keep using `169.254.17.2`.
- Ztunnel continues to use the Worker Pod SPIFFE certificate for mTLS.
- The Actor private key is never sent over ADS/WCDS.
- Missing or malformed Actor binding labels produce no `ActorContext`.
- Actor token lookup is exact by Actor UID; never select the first token in the directory.
- The binding generation is non-zero and changes whenever a Worker is reassigned.
- Preserve legacy sandbox header names for compatibility with the current gateway/EPE path.

---

### Task 1: Define and generate the ActorContext wire contract

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions/agentioconfig.proto`
- Regenerate: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions/agentioconfig.pb.go`
- Regenerate: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions/agentioconfig_json.gen.go`
- Regenerate: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions/agentioconfig_vtproto.pb.go`
- Modify in ztunnel: `proto/extensions.proto`

**Interfaces:**
- Produces: `ActorContext { actor_uid, actor_name, atespace, generation, labels }`.
- Produces: optional `WorkloadConfig.actor_context` field number 3.

- [ ] **Step 1: Add failing Go tests that construct and inspect `ActorContext`.**

```go
func TestActorContextFromLabels(t *testing.T) {
    got := ActorContextFromLabels(map[string]string{
        LabelActorUID: "actor-1", LabelActorName: "crawler",
        LabelActorAtespace: "demo", LabelActorGeneration: "7",
        ActorLabelPrefix + "role": "reader",
    })
    assert.Equal(t, got.GetActorUid(), "actor-1")
    assert.Equal(t, got.GetGeneration(), uint64(7))
    assert.Equal(t, got.GetLabels()["role"], "reader")
}
```

- [ ] **Step 2: Run `go test ./pilot/pkg/serviceregistry/kube/controller/agentio -run TestActorContextFromLabels -count=1` and verify it fails because the contract is absent.**
- [ ] **Step 3: Add the proto messages and run `./tools/proto/generate-agentio.sh`.**
- [ ] **Step 4: Copy the same wire-compatible message definitions to ztunnel's `proto/extensions.proto`.**
- [ ] **Step 5: Re-run the focused Go test and verify it passes.**

### Task 2: Derive and target ActorContext from Worker workload state

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs.go`
- Test: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions_test.go`
- Test: `pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs_test.go`

**Interfaces:**
- Produces: `ActorContextFromLabels(map[string]string) *extensions.ActorContext`.
- Consumes Worker labels `networking.agents.kruise.io/actor-{uid,name,atespace,generation}`.
- Copies labels with prefix `actor.networking.agents.kruise.io/` into Actor labels with the prefix removed.

- [ ] **Step 1: Test complete, missing, zero-generation, non-numeric, and prefixed-label bindings.**
- [ ] **Step 2: Run the focused tests and verify the missing function fails compilation.**
- [ ] **Step 3: Implement strict parsing with `strconv.ParseUint`, returning nil for incomplete bindings.**
- [ ] **Step 4: Test `WorkloadConfigsForProxy` clones the global config, adds only the calling Worker's ActorContext, and clears it after labels are removed.**
- [ ] **Step 5: Implement lookup through `BuildProxyWorkloadKey(proxy)` and `a.workloads.GetKey`, without mutating the shared singleton config.**
- [ ] **Step 6: Run both focused Go packages and verify green.**

### Task 3: Push WCDS again when the Worker's Actor assignment changes

**Files:**
- Modify: `pilot/pkg/xds/workload.go`
- Test: `pilot/pkg/xds/workload_test.go`

**Interfaces:**
- Produces: `workloadConfigNeedsPush(proxy, req) bool` for a dedicated ztunnel's own workload address update.

- [ ] **Step 1: Add a failing table test proving unrelated address changes do not trigger WCDS, while the Worker's own address does.**
- [ ] **Step 2: Run `go test ./pilot/pkg/xds -run TestWorkloadConfigNeedsPush -count=1` and verify red.**
- [ ] **Step 3: Teach `WorkloadConfigGenerator.GenerateDeltas` to regenerate current resource names when that predicate is true.**
- [ ] **Step 4: Re-run the focused test and existing workload generator tests.**

### Task 4: Store ActorContext in ztunnel and inject trusted HBONE metadata

**Files:**
- Modify: `src/state/workload_config.rs`
- Modify: `src/xds.rs`
- Modify: `src/sandbox/sandbox.rs`
- Modify: `src/proxy/outbound.rs`
- Test: tests embedded in the same Rust modules.

**Interfaces:**
- Produces: Rust `ActorContext` with deterministic base64 label encoding.
- Produces headers `x-agentio-sandbox-id`, `x-agentio-sandbox-generation`, `x-agentio-sandbox-labels`, and Actor-specific `x-agentio-sandbox-token`.

- [ ] **Step 1: Add a failing xDS handler test that stores and replaces an ActorContext.**
- [ ] **Step 2: Add a failing HBONE request test that supplies two token files and proves the Actor UID selects only its matching token.**
- [ ] **Step 3: Run the two Rust test filters through the build container and verify red.**
- [ ] **Step 4: Convert proto ActorContext to internal state, encode sorted labels, and expose the current context.**
- [ ] **Step 5: Remove first-token selection and inject headers only from the current ActorContext plus exact token lookup.**
- [ ] **Step 6: Run the focused Rust tests and verify green.**

### Task 5: Relay Actor generation and expose Actor identity to EPE

**Files:**
- Modify: `pilot/pkg/xds/filters/filters.go`
- Modify: `pilot/pkg/xds/filters/filters_test.go`
- Modify: `manifests/charts/agentio/templates/agentio-config.yaml`
- Modify: `extensions/epe/pkg/engine/filter/peer.go`
- Modify: `extensions/epe/pkg/extproc/attributes/extract.go`
- Modify: `extensions/epe/pkg/extproc/attributes/extract_test.go`

**Interfaces:**
- Produces filter state `sandbox.generation` from `X-AGENTIO-SANDBOX-GENERATION`.
- Produces `Peer.ActorUID string` and `Peer.ActorGeneration uint64` while retaining Worker Pod identity.

- [ ] **Step 1: Extend filter and EPE extraction tests first; verify failures for the missing relay and fields.**
- [ ] **Step 2: Add the generation relay and chart request attribute.**
- [ ] **Step 3: Parse UID and generation into `Peer`; malformed generation becomes zero.**
- [ ] **Step 4: Run focused filter and EPE tests.**

### Task 6: Document and verify the PoC

**Files:**
- Create: `docs/integrations/actor-identity-worker-mtls-poc.md`

**Interfaces:**
- Documents the Worker label contract, token filename contract, WCDS/HBONE flow, verification commands, and the PoC security boundary.

- [ ] **Step 1: Document exact `kubectl label` and token mount examples.**
- [ ] **Step 2: Run `gofmt` and `cargo fmt` through available toolchains.**
- [ ] **Step 3: Run focused Go tests, EPE tests, proto wire checks, Helm lint/templates, Rust tests, and `git diff --check`.**
- [ ] **Step 4: Review diffs for generated-only changes and unrelated files.**
- [ ] **Step 5: Commit the Agentio branch; commit ztunnel only if covered by the user's implementation-and-commit authorization, otherwise leave its cleanly scoped diff ready for review.**
