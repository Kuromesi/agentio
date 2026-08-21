# Substrate ListWorkers Actor 身份接入设计

## 背景

现有 ActorContext PoC 从 Worker Pod labels 获取 Actor 绑定。这能验证 WCDS、ztunnel 和 gateway 协议，但不是社区 Substrate 的正式状态来源，也要求在每次 Actor 迁移时修改 Pod labels。

社区 Substrate 的公开 `ateapi.Control/ListWorkers` RPC 返回 Worker Pod 的 namespace、name、UID，以及当前 `ActorAssignment`。本 PoC 将它作为 agentiod 的 Actor 绑定事实来源。

## 方案

agentiod 启用 ListWorkers 集成后：

1. 使用 PodIdentity 客户端证书和 ServiceDNS 信任根，通过 mTLS 连接 `api.ate-system.svc:443`。
2. 周期性分页调用 `ListWorkers`，构建 `(worker namespace, pod name, pod UID) -> ActorContext` 快照。
3. Actor UID、name、atespace 来自 `ActorAssignment`；Worker `metadata.version` 作为绑定 generation。该版本在 Worker assignment 变化时递增，能够防止同一 Worker 复用旧连接。
4. 快照变化时触发一次强制 xDS push；目标 ztunnel 随后收到定向 WCDS ActorContext。
5. 通过 Kubernetes 原生 Pod UID 校验当前 workload 与 ListWorkers 中的 Worker，避免同名 Pod 重建后误用旧绑定。
6. ListWorkers 启用后是权威数据源：没有 assignment 时明确不下发 ActorContext；轮询失败时保留最后一次成功快照。Pod label 解析仅在该功能未启用时作为兼容路径。

## 协议与依赖边界

Agentio 不直接依赖 `github.com/agent-substrate/substrate`：社区模块要求 Go 1.26，而 Agentio 当前使用 Go 1.25。仓库内增加最小 wire-compatible proto，只声明 ListWorkers 所需字段和相同的 `ateapi.Control` 服务名、字段号。生成代码继续由 `tools/proto/generate-agentio.sh` 管理。

## 配置

Helm 增加默认关闭的 `agentiod.substrateListWorkers`。启用后自动设置客户端环境变量，并投影：

- `podidentity.podcert.ate.dev/identity` 签发的客户端 credential bundle；
- `servicedns.podcert.ate.dev/identity` 的 ClusterTrustBundle，用于验证 ateapi 服务端证书。

## 限制

- `ListWorkers` 没有 watch RPC，因此 PoC 使用轮询，状态收敛延迟取决于间隔。
- Worker assignment 不含 Actor 自定义 labels 和 Actor 运行状态；PoC 只生成标准身份、ActorTemplate 和 WorkerPool labels。
- Worker `metadata.version` 可能因非 assignment 更新递增，安全上不会串用身份，但可能导致一次额外连接排空。
- 当前方案仍对应一个 Worker 同时只绑定一个 Actor。
