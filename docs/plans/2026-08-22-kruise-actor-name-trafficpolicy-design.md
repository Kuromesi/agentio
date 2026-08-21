# Kruise Actor Name 与 TrafficPolicy Pod Selector 验证设计

## 目标

1. ActorContext labels 使用 `kruise.io/actor-name` 作为 Actor 名称的标准策略键。
2. 已存在的 `agentio.io/actor-name` 在过渡期继续下发，避免旧 `SecurityProfile` 立即失效。
3. `TrafficPolicy.spec.selector` 保持 Kubernetes Pod label 语义，不读取或合并 ActorContext labels。
4. 在 `my-ecs` 的 `substrate-poc` 集群用真实 Actor 流量验证 Actor 级 EPE 策略和 Pod 级四层 TrafficPolicy。

## 方案比较

### 方案 A：直接替换旧键

只输出 `kruise.io/actor-name`。实现最小，但所有使用 `agentio.io/actor-name` 的现有策略会在升级后立即失效。

### 方案 B：标准键与旧键双写

ActorContext 同时输出：

```text
kruise.io/actor-name=<actor-name>
agentio.io/actor-name=<actor-name>
```

新策略和文档只使用 `kruise.io/actor-name`，旧键标记为兼容 alias。额外开销只有一个短 label，能够支持无中断迁移。这是本 PoC 采用的方案。

### 方案 C：把 Actor labels 合并进 Workload labels

这样 TrafficPolicy 可以看似直接匹配 Actor，但会混淆 Pod 生命周期与 Actor assignment，破坏 TrafficPolicy 现有 Kubernetes selector 语义，并使同 Worker 多 Actor 演进更加困难，因此不采用。

## 标签数据流

ListWorkers 和 Pod-label fallback 两条 ActorContext 构建路径都生成标准键与兼容键，值必须完全一致。Actor 名称仍来自可信的 Substrate assignment；不修改 Worker Pod labels，也不把 ActorContext labels 写回 Kubernetes Workload labels。

ztunnel 从源 Worker 的 WDS `Workload.extensions["actor-context"]` 读取 labels，在存在 ActorContext 时把它们编码为 `x-agentio-sandbox-labels`。Gateway 写入 `filter_state["sandbox.labels"]`，EPE 使用该 map 匹配 `SecurityProfile.spec.selector`。因此新策略可以直接使用：

```yaml
selector:
  matchLabels:
    kruise.io/actor-name: actor-name
```

## TrafficPolicy 边界

TrafficPolicy 不做代码变更：

- Sidecar 继续用专用 proxy 的 Kubernetes Pod labels 选择策略。
- Ambient 继续用 WDS Workload 对应的 Kubernetes Pod labels 绑定策略。
- `from/to.workload.selector` 继续把 Pod selector 解析为 Pod IP 集合。
- ActorContext 只影响 Gateway/EPE Actor 身份，不参与 TrafficPolicy attachment。

## 验证设计

### 自动化测试

- `ActorContextFromLabels` 必须同时生成两个 Actor name key，且值相同。
- ListWorkers assignment 必须同时生成两个 Actor name key，且值相同。
- 现有 ActorContext、WDS、WCDS 和 TrafficPolicy 单元测试全部保持通过。

### 集群 Actor/EPE 验证

启动测试 Actor，确认 Sidecar WDS ActorContext 中存在 `kruise.io/actor-name`。启用 EPE 和 GATEWAY 选路，创建只匹配新键的 `SecurityProfile`：目标 Actor 的特定 HTTP path 必须被拦截，控制 path 必须放行；Gateway/EPE 证据中不得依赖 Worker Pod 上存在 Actor label。

### 集群 TrafficPolicy 验证

使用同一个 Actor 和同一组请求执行 selector A/B：

1. `spec.selector` 使用不存在的 Pod label，策略不得附加，请求保持成功。
2. selector 改为 Worker 的真实 label `ate.dev/worker-pool=egress`，策略必须附加。
3. egress rule 拒绝测试 backend CIDR，Actor 发起的对应出向请求失败；删除或切回不匹配 selector 后恢复。
4. ingress rule 拒绝 Substrate router Pod CIDR，访问该 Actor 失败；不匹配 selector 时访问成功。

该测试同时保存专用 ztunnel config dump，证明流量结果与 policy attachment 一致。

## 恢复与发布

- 测试前备份 Helm values、AgentioConfig、mesh ConfigMap 和已有 TrafficPolicy/SecurityProfile。
- 测试后删除临时 Actor、策略和 Service，移除测试 Pod label，恢复配置并关闭临时 EPE。
- pilot 发布顺序不改变：先确保 ztunnel 支持 Workload ActorContext，再升级 agentiod。
- 兼容 alias 至少保留一个迁移周期；移除前必须确认线上已不存在 `agentio.io/actor-name` selector。

