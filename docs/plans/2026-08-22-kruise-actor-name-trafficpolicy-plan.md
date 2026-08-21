# Kruise Actor Name 与 TrafficPolicy Pod Selector 验证实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 Actor 级 EPE 策略使用 `kruise.io/actor-name`，同时保留旧键兼容，并用真实集群流量证明 TrafficPolicy 仍按 Worker Pod label 匹配。

**Architecture:** Agentiod 在 ActorContext labels 中双写 canonical 与 legacy Actor name key；ztunnel 和 EPE 沿用现有 ActorContext/HBONE/filter-state 数据流。TrafficPolicy 不读取 ActorContext，继续由控制面使用 Kubernetes Pod labels 做 policy attachment。

**Tech Stack:** Go、Istio WDS、Kubernetes LabelSelector、Rust ztunnel、Envoy ext_proc、Agentio EPE、Substrate、Helm、KinD。

## Global Constraints

- 新策略键必须是 `kruise.io/actor-name`。
- `agentio.io/actor-name` 只作为迁移兼容 alias，值必须与新键相同。
- 不修改 Worker Pod Actor labels，不把 ActorContext labels 合并进 Workload labels。
- TrafficPolicy 继续只根据 Kubernetes Pod labels、namespace、peer、端口和协议匹配。
- 集群测试必须包含 selector 不匹配与匹配两种对照，并恢复所有临时状态。

---

### Task 1: TDD 增加标准 Actor name label

**Files:**
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/extensions.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/actor_context_test.go`
- Modify: `pilot/pkg/serviceregistry/kube/controller/agentio/substrate_workers_test.go`

**Interfaces:**
- Consumes: `ActorContextFromLabels(map[string]string)` 和 `actorContextFromSubstrateAssignment(...)`。
- Produces: ActorContext `Labels` 同时包含 `kruise.io/actor-name` 与 `agentio.io/actor-name`。

- [ ] **Step 1: 写失败测试**

在两个测试中使用手工字面量断言：

```go
if got := actor.GetLabels()["kruise.io/actor-name"]; got != "crawler" {
    t.Fatalf("kruise.io/actor-name = %q, want crawler", got)
}
if got := actor.GetLabels()["agentio.io/actor-name"]; got != "crawler" {
    t.Fatalf("legacy agentio.io/actor-name = %q, want crawler", got)
}
```

ListWorkers 测试使用 Actor 名 `actor-a` 做同样断言。生产代码缺少 canonical key 时，测试必须失败。

- [ ] **Step 2: 验证 RED**

Run:

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/agentio \
  -run 'TestActorContextFromLabels|TestSubstrateWorkerSourceBuildsActorContextFromAllPages' -count=1
```

Expected: FAIL，`kruise.io/actor-name` 实际值为空。

- [ ] **Step 3: 最小实现双写**

将 canonical 常量设为 `kruise.io/actor-name`，新增 legacy 常量 `agentio.io/actor-name`，并在 Pod-label fallback 与 ListWorkers assignment 的 ActorContext labels 中同时写入两个键。

- [ ] **Step 4: 验证 GREEN 和相关回归**

Run:

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/agentio/... \
  ./pilot/pkg/serviceregistry/kube/controller/ambient ./pilot/pkg/xds -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交实现**

```bash
git add pilot/pkg/serviceregistry/kube/controller/agentio/extensions.go \
  pilot/pkg/serviceregistry/kube/controller/agentio/actor_context_test.go \
  pilot/pkg/serviceregistry/kube/controller/agentio/substrate_workers_test.go
git commit -m "agentio: add kruise actor name policy label"
```

### Task 2: 构建与 Actor/EPE 集群验证

**Files:**
- Runtime evidence: `my-ecs:/opt/substrate-poc/agentio-kruise-actor-trafficpolicy-20260822/`

**Interfaces:**
- Consumes: Task 1 的 agentiod 镜像和现有 `actor-workload-poc-v1` ztunnel。
- Produces: WDS canonical label 与 EPE `SecurityProfile` 新键命中的端到端证据。

- [ ] **Step 1: 保存测试前状态并构建 pilot**

在证据目录保存 Helm values、AgentioConfig、mesh ConfigMap、Worker/Actor/策略资源。把新分支同步到远端构建目录，构建并推送 `localhost:5000/pilot:kruise-actor-name-poc-v1`，保存 image ID 与 registry digest。

- [ ] **Step 2: 升级 agentiod 并启用临时 EPE**

使用 `helm upgrade --reuse-values` 更新 pilot tag 并设置 `epe.enabled=true`；等待 agentiod、gateway 和 EPE Ready。ztunnel 继续使用 `actor-workload-poc-v1`。

- [ ] **Step 3: 创建 Actor 并验证 WDS label**

创建并 resume `kruise-label-20260822`，等待 RUNNING。保存分配 Worker 的 config dump，断言：

```text
kruise.io/actor-name=kruise-label-20260822
agentio.io/actor-name=kruise-label-20260822
Worker Pod 不含这两个 Actor name label
```

- [ ] **Step 4: 验证 SecurityProfile 新键**

把测试 backend 配为 GATEWAY，创建以下选择器的 SecurityProfile：

```yaml
selector:
  matchLabels:
    kruise.io/actor-name: kruise-label-20260822
```

目标 path 返回自定义拦截状态码，控制 path 返回 `200`；保存 gateway access log 和 EPE 日志。

### Task 3: TrafficPolicy Pod selector 集群验证

**Files:**
- Runtime evidence: `my-ecs:/opt/substrate-poc/agentio-kruise-actor-trafficpolicy-20260822/trafficpolicy/`

**Interfaces:**
- Consumes: Task 2 的运行中 Actor、Worker Pod label `ate.dev/worker-pool=egress`、backend IP 和 router Pod IP。
- Produces: TrafficPolicy selector 不匹配/匹配时入向和出向流量的 A/B 证据。

- [ ] **Step 1: 建立不匹配 selector 对照**

创建 TrafficPolicy，selector 为：

```yaml
matchLabels:
  agentio.io/trafficpolicy-poc: not-present
```

配置 egress reject backend `/32` 和 ingress reject router Pod `/32`。等待控制面收敛，断言目标 Worker 没有附加测试 policy，Actor 入向访问和 Actor 到 backend 出向请求仍成功。

- [ ] **Step 2: 切换到真实 Pod label 并验证 egress**

只把 selector 更新为：

```yaml
matchLabels:
  ate.dev/worker-pool: egress
```

等待测试 policy 附加到 Worker，调用 Actor egress demo 请求 backend，断言外层请求返回失败且错误对应被拒绝的目标连接；访问未被 egress rule 匹配的目标保持成功。

- [ ] **Step 3: 验证 ingress**

保留真实 Pod selector，把 ingress reject source 设为当前 `atenet-router` Pod IP `/32`。通过 router 访问 Actor，断言请求失败；把 selector 切回不存在的 label 后同一请求恢复成功。

- [ ] **Step 4: 保存配置与流量证据**

保存每个阶段的 TrafficPolicy YAML、ztunnel config dump、Actor 请求响应和 ztunnel 日志，汇总 selector、policy attachment 与流量结果的对应关系。

### Task 4: 恢复、文档、回归和推送

**Files:**
- Modify: `docs/integrations/actor-identity-worker-mtls-poc.zh-CN.md`
- Modify: `docs/integrations/actor-identity-worker-mtls-poc.md`

**Interfaces:**
- Consumes: Task 1 代码、Task 2/3 集群证据。
- Produces: 可复查的标签迁移与 TrafficPolicy 边界文档、清洁并已推送的分支。

- [ ] **Step 1: 恢复集群**

删除临时 Actor、SecurityProfile、TrafficPolicy 和测试 Service；恢复 AgentioConfig、mesh ConfigMap 与 Helm EPE 设置。保留新 pilot 镜像部署，确认 agentiod/gateway/ztunnel/CNI/Worker Ready，测试资源不存在。

- [ ] **Step 2: 更新文档**

把新策略示例改为 `kruise.io/actor-name`，记录 legacy alias、TrafficPolicy Pod selector 边界、入向/出向 A/B 结果、镜像 digest、证据目录、恢复状态和已知限制。

- [ ] **Step 3: 最终回归**

Run:

```bash
go test ./pilot/pkg/serviceregistry/kube/controller/agentio/... \
  ./pilot/pkg/serviceregistry/kube/controller/ambient ./pilot/pkg/bootstrap -count=1
go test ./pilot/pkg/xds -run 'TestWorkloadConfig|TestXdsCache' -count=1
go test ./extensions/epe/pkg/... -count=1
git diff --check
```

Expected: 所有 Go/EPE 测试通过，`git diff --check` 无输出。

- [ ] **Step 4: 提交文档并推送分支**

```bash
git add docs/integrations/actor-identity-worker-mtls-poc.zh-CN.md \
  docs/integrations/actor-identity-worker-mtls-poc.md
git commit -m "docs: record actor label and traffic policy validation"
git push -u origin codex/kruise-actor-name-trafficpolicy-poc
```
