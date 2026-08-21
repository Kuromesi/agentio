# Sidecar Workload ActorContext Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 Sidecar 与 Ambient 都只通过 WDS `Workload.extensions` 接收当前 ActorContext，不再由 agentiod 通过 WCDS 重复下发 Actor 身份。

**Architecture:** 保留现有 `ActorContext` protobuf、Workload extension 编解码及 ztunnel WCDS fallback，控制面只删除 WCDS 动态身份注入和 Actor address update 触发的 WCDS push。Substrate `ListWorkers` 变化继续生成精确的 `AddressesUpdated`，Sidecar 与 Ambient 都由源 Worker Workload 更新触发 per-Workload drain。

**Tech Stack:** Go、Istio WDS/WCDS、protobuf Any、Rust ztunnel、Helm、KinD。

## Global Constraints

- Substrate `ListWorkers` 仍是 Actor assignment 的权威来源。
- Sidecar WDS 只在自身 Worker Workload 上携带 ActorContext。
- WCDS 继续承载流量配置，但新 agentiod 不得填充 `WorkloadConfig.actor_context`。
- 不删除 protobuf 字段或 ztunnel WCDS fallback，保持 wire 与回滚兼容。
- Actor suspend/resume 必须通过 Workload delta 清除/更新身份并按 Workload drain。
- 不修改 Worker Pod Actor labels，不改 ztunnel Worker mTLS 证书模型。

---

### Task 1: 控制面切换到 WDS-only ActorContext

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs_test.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs.go`
- Modify: `pilot/pkg/xds/workload.go`
- Modify: `pilot/pkg/xds/workload_actor_test.go`

**Interfaces:**
- Consumes: `index.attachActorContextsForProxy(*model.Proxy, []model.AddressInfo)` 和 `PushRequest.AddressesUpdated`。
- Produces: WCDS 中 `WorkloadConfig.actor_context == nil`，WDS 中 dedicated Sidecar 自身 Workload extension 保持不变。

- [ ] **Step 1: 写 WCDS 不再携带 ActorContext 的失败测试**

将 dedicated ztunnel 的 WCDS 测试改为断言：即使 Worker labels 或权威 ListWorkers binding 存在，`WorkloadConfigsForProxy` 返回的 global config 也保持 `actor_context == nil`，并且不会修改共享 `WorkloadConfig`。

- [ ] **Step 2: 运行测试并确认按预期失败**

Run: `go test ./pilot/pkg/serviceregistry/kube/controller/ambient -run 'TestWorkloadConfigsForProxyDoesNotAttachActorContext' -count=1`

Expected: FAIL，因为当前实现会把 ActorContext 克隆进 global WCDS config。

- [ ] **Step 3: 删除 WCDS Actor 动态注入**

让 `WorkloadConfigsForProxy` 仅执行 dedicated proxy 的 namespace/system namespace 过滤和 requested config 过滤，直接返回配置，不再调用 `actorContextForProxy` 或写入 `ext.Config.ActorContext`。保留 `actorContextForWorkload`，因为 WDS extension 装饰仍依赖它。

- [ ] **Step 4: 删除 address-only WCDS push 分支**

把 `WorkloadConfigGenerator.GenerateDeltas` 的全量分支恢复为只检查 `req.Forced`，删除 `workloadConfigNeedsPush` 及其专用测试。Actor binding callback 仍保留 `AddressesUpdated`，由 `WorkloadGenerator` 处理 WDS delta。

- [ ] **Step 5: 运行聚焦与相关回归测试**

Run:

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/ambient \
  ./pilot/pkg/serviceregistry/kube/controller/agentio/... \
  ./pilot/pkg/xds ./pilot/pkg/bootstrap -count=1
```

Expected: PASS。

- [ ] **Step 6: 提交控制面改造**

```bash
git add pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs.go \
  pilot/pkg/serviceregistry/kube/controller/ambient/workload_configs_test.go \
  pilot/pkg/xds/workload.go pilot/pkg/xds/workload_actor_test.go
git commit -m "agentio: move sidecar actor context to workload api"
```

### Task 2: Kind 集群 WDS-only 端到端验证

**Files:**
- Runtime evidence: `my-ecs:/opt/substrate-poc/agentio-sidecar-workload-extension-20260822/`

**Interfaces:**
- Consumes: Agentio pilot image containing Task 1 and existing `localhost:5000/ztunnel:actor-workload-poc-v1`。
- Produces: Sidecar WDS-only、Ambient 不回归、Actor lifecycle 与 gateway identity 的集群证据。

- [ ] **Step 1: 构建并推送 pilot PoC 镜像**

使用 Task 1 commit 构建 `localhost:5000/pilot:actor-workload-poc-v2`，推送到 `my-ecs` 本地 registry，并保存镜像 digest。

- [ ] **Step 2: 升级 agentiod 并保存测试前状态**

保留 Sidecar/Ambient 与现有 ztunnel 镜像配置，仅把 `agentiod.image.tag` 更新为 `actor-workload-poc-v2`。备份 Helm values、AgentioConfig 和 mesh ConfigMap。

- [ ] **Step 3: 验证 Sidecar WDS-only 身份链**

创建 Sidecar Actor 并等待 RUNNING，断言：

```text
assigned sidecar WDS own Workload ActorContext = expected UID/generation
unassigned sidecar WDS ActorContext = absent
assigned sidecar WCDS WorkloadConfig.actor_context = absent
```

通过 PASSTHROUGH、DENY 和 GATEWAY 请求验证策略；gateway 必须记录预期 Actor UID/generation。

- [ ] **Step 4: 验证 Sidecar lifecycle 与 drain**

suspend 后 WDS extension 清除，ztunnel 记录按 Worker Workload UID 的 targeted drain，不得出现由本次变更触发的 WCDS 全量 Actor drain；resume 后 generation 更新，gateway 使用新 generation。

- [ ] **Step 5: 验证 Ambient 不回归**

创建无 sidecar、带 `istio.io/reroute-virtual-interfaces=ateom0` 的临时 Ambient Worker 和 Actor，确认 WDS extension、GATEWAY Actor UID/generation 及 suspend 清除仍然正确。

- [ ] **Step 6: 清理并恢复集群**

删除临时 Actor、Ambient Worker、ActorTemplate、WorkerPool、测试 Service 与策略；恢复测试前 AgentioConfig/mesh，确认 agentiod、gateway、ztunnel、CNI 及原 Sidecar Worker Ready。

### Task 3: 文档、全量回归与推送

**Files:**
- Modify: `docs/integrations/actor-identity-worker-mtls-poc.zh-CN.md`

**Interfaces:**
- Consumes: Task 1 代码和 Task 2 集群证据。
- Produces: 中文 WDS-only Sidecar 验证记录和已推送分支。

- [ ] **Step 1: 更新中文 PoC 文档**

记录控制面切换、WCDS/WDS 对照、Sidecar/Ambient 实测、lifecycle drain、gateway identity、镜像 digest、证据目录和恢复状态；把旧的“Sidecar 使用 WCDS 身份”描述改为历史兼容说明。

- [ ] **Step 2: 运行最终回归**

Run:

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/agentio/... \
  ./pilot/pkg/serviceregistry/kube/controller/ambient ./pilot/pkg/bootstrap -count=1
go test ./pilot/pkg/xds -run 'TestWorkloadConfig|TestXdsCache' -count=1
go test ./extensions/epe/pkg/... -count=1
PROTOC=/tmp/agentio-protoc-29.3/bin/protoc \
  cargo test --manifest-path ../ztunnel/.worktrees/actor-context-poc/Cargo.toml \
  --lib -- --test-threads=1 --skip tls::certificate::test::multi_root
git diff --check
```

Expected: Go/EPE 全部通过；ztunnel `344 passed, 0 failed, 1 filtered out`；`git diff --check` 无输出。

- [ ] **Step 3: 提交文档并推送**

```bash
git add docs/integrations/actor-identity-worker-mtls-poc.zh-CN.md
git commit -m "docs: record sidecar workload extension validation"
git push origin codex/actor-context-poc
```

