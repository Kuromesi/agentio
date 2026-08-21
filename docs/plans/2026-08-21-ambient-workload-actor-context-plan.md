# Ambient Workload ActorContext Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过 Workload API typed extension 将 Substrate Actor assignment 定向下发给 sidecar 和 node-level Ambient ztunnel。

**Architecture:** agentiod 动态克隆 Worker Workload 并追加 ActorContext Any extension；ListWorkers 变化触发受影响 Workload 的 Address delta。ztunnel 把扩展解码到源 Workload，按连接源选择 HBONE Actor headers，并只 drain Actor 绑定发生变化的 Workload 连接。

**Tech Stack:** Go、KRT、Istio Address xDS、protobuf Any、Rust、tokio watch、KinD。

## Global Constraints

- ListWorkers 启用后是权威来源，未分配状态不得回退 Pod Actor labels。
- Actor token 不得进入 Workload API。
- Kubernetes Pod UID 必须参与控制面匹配。
- 保留 WCDS ActorContext 作为 sidecar 迁移兼容路径。
- 不修改 `istio.workload.Workload` protobuf schema，只使用已有 `extensions = 26`。

---

### Task 1: ActorContext Workload extension 编码

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions.go`
- Test: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions_package_test.go`

**Interfaces:**
- Produces: `NewActorContextExtension(*extensions.ActorContext) *workloadapi.Extension`

- [ ] 写测试，断言 extension name、type URL 和反序列化后的 Actor UID/generation。
- [ ] 运行聚焦测试并确认因 helper 缺失失败。
- [ ] 添加 `ActorContext` type URL 常量和编码 helper。
- [ ] 运行聚焦测试并确认通过。

### Task 2: 按 proxy 装饰 Workload 并触发 Address delta

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/ambient/ambientindex.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/controller.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/substrate_workers.go`
- Modify: `pilot/pkg/bootstrap/configcontroller.go`
- Test: `pilot/pkg/serviceregistry/kube/controller/ambient/ambientindex_test.go`
- Test: `pilot/pkg/serviceregistry/kube/controller/agentio/substrate_workers_test.go`

**Interfaces:**
- Consumes: `NewActorContextExtension`
- Produces: `ActorBindingWorkload{Namespace, PodName}` change notifications and proxy-scoped AddressInfo cloning。

- [ ] 写失败测试：node ztunnel 只在本节点 Worker Workload 上看到 ActorContext，远端节点与共享基础对象没有扩展。
- [ ] 写失败测试：dedicated sidecar 只在自身 Workload 上看到 ActorContext，authoritative nil 清除扩展。
- [ ] 写失败测试：ListWorkers callback 返回新增、变更和删除绑定的 Worker keys，失败刷新不通知。
- [ ] 实现动态 Workload clone/extension 装饰及 label fallback。
- [ ] 实现 binding diff 通知，并在 bootstrap 构造受影响 Workload UID 的 `AddressesUpdated`。
- [ ] 运行 Agentio、Ambient 与 xDS 聚焦测试。

### Task 3: ztunnel 解码并保存 Workload ActorContext

**Files:**
- Modify: `src/extensions/extensions.rs`
- Modify: `src/state/workload.rs`
- Modify: `src/state/workload_config.rs`

**Interfaces:**
- Consumes: `type.googleapis.com/kruise.networking.extensions.v1.ActorContext`
- Produces: `Workload.actor_context: Option<ActorContext>`

- [ ] 写失败测试：包含 ActorContext extension 的 XdsWorkload 转换后保留 UID、generation、排序编码 labels。
- [ ] 写失败测试：缺少必要字段或 generation 为零时拒绝该 Workload 更新。
- [ ] 增加 typed extension 解码和内部 Workload 字段，复用现有 ActorContext 校验。
- [ ] 运行 Rust Workload/extension 聚焦测试。

### Task 4: 按源 Workload 发送 Actor headers

**Files:**
- Modify: `src/proxy/outbound.rs`

**Interfaces:**
- Consumes: `Request.source.actor_context`
- Produces: `x-agentio-sandbox-id`、generation、labels 和精确 Actor token header。

- [ ] 写失败测试：源 Workload ActorContext 覆盖不同的全局 WCDS ActorContext。
- [ ] 写失败测试：没有源 ActorContext 和全局 ActorContext 时不发送 Actor UID/generation。
- [ ] 修改 HBONE request builder，优先使用源 Workload并保留 WCDS 兼容 fallback。
- [ ] 运行 outbound 聚焦测试。

### Task 5: per-Workload Actor binding drain

**Files:**
- Modify: `src/proxy/connection_manager.rs`

**Interfaces:**
- Consumes: `WorkloadStore` 更新通知和连接中保存的源 Workload UID/ActorContext。
- Produces: 仅关闭 Actor `(uid, generation)` 发生变化的 Workload 连接。

- [ ] 写失败测试：更新 Worker A Actor 只关闭 A 连接，Worker B 连接保持。
- [ ] 写失败测试：删除 Worker A ActorContext 关闭 A 连接。
- [ ] 订阅 WorkloadStore，按 Workload UID 比较旧/新 Actor binding 并选择性 drain。
- [ ] 运行 connection manager 和完整 Rust lib 聚焦测试。

### Task 6: 集群验证、文档与推送

**Files:**
- Modify: `docs/integrations/actor-identity-worker-mtls-poc.zh-CN.md`

- [ ] 构建并推送 Agentio pilot 与 ztunnel PoC 镜像到 `my-ecs` 本地 registry。
- [ ] 部署独立 Ambient Worker，确认没有 Pod Actor labels。
- [ ] 创建 Actor，确认 ListWorkers assignment 和 node ztunnel Workload extension一致。
- [ ] 验证 PASSTHROUGH、GATEWAY、Actor headers 与 per-Worker drain。
- [ ] 暂停/删除临时 Actor 和资源，恢复 PASSTHROUGH。
- [ ] 运行 Go、Rust、Helm、版权和 diff 最终验证。
- [ ] 更新中文 PoC 文档，提交并推送 Agentio 与 ztunnel 分支。
