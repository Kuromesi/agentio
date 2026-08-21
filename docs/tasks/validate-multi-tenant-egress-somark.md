# 多租户 Egress 身份路由与 SO_MARK POC 验证记录

## 结论

方案在架构上可行，推荐边界如下：

1. 一套共享出口网关可以承载多个租户；
2. 网关从可信的 downstream peer metadata 识别租户，不接受业务 Pod 声明的 tenant/mark；
3. 每个租户使用独立 Envoy cluster，`SO_MARK` 静态配置在 cluster 的 upstream socket option；
4. HTTP connection pool 和 UDP socket 均不跨租户共享；
5. mark 更新必须带 generation，生成新 cluster 名并排空旧 socket；
6. mark 只负责把流量导向对应策略路由，完整隔离仍依赖宿主机 `ip rule`、路由表和 VXLAN/VNI/VRF 等数据面配置。

当前新增的可配置 bundle 已完成本地单元测试、Wasm 构建、YAML 解析和 Kubernetes client-side dry-run，但本次尚未把它应用到 `cluster-1VOH82`。因此不能把“当前 `downstream_peer.namespace/name` + CONNECT-UDP + 每租户 mark”标记为已完成 live runtime 验证。

## 验证状态

| 验证层 | 状态 | 说明 |
| --- | --- | --- |
| 配置源 | 已验证 | `tenants.yaml` 可配置 tenant、workload、generation 和 mark；非法/重复映射被拒绝 |
| Wasm 原生逻辑 | 已验证 | 精确身份查找、HTTP 触发条件、CONNECT-UDP 精确请求形状测试通过 |
| Wasm 构建 | 已验证 | `wasm32-wasip1 --release --lib` 成功 |
| 渲染结果 | 已验证 | ConfigMap 内含 HTTP/UDP 两份 EnvoyFilter；tenant cluster/route/mark/filter 顺序语义测试通过 |
| Kubernetes client dry-run | 已验证 | ConfigMap 和 6 个 UDP 测试资源均通过 `kubectl apply --dry-run=client` |
| 控制面读取 ConfigMap | 待验证 | 需要在目标集群检查 config-source controller 和 EnvoyFilter 状态 |
| 活动 xDS | 待验证 | 需要从目标 waypoint config dump 检查 filter、route、cluster 和 socket option |
| UDP runtime | 待验证 | 需要分别发送 tenant-a、tenant-b 和 unknown 请求 |
| 实际 SO_MARK 权限 | 待验证 | 需要证明默认 capability 失败，以及临时 NET_ADMIN 后成功 |

## 历史 live POC 与当前实现的关系

此前同一任务在 `cluster-1VOH82` 做过两类分步验证：

- cluster 级 `upstream_bind_config.socket_options` 能生成 `SOL_SOCKET/SO_MARK` 配置；默认权限下 Envoy 会报告 socket option 设置失败，临时具备 `NET_ADMIN` 后可继续建连；
- HTTP Wasm 能读取网关 relayed identity、删除伪造的内部 route header、调用 `clear_route_cache`，并切换到租户独立 cluster；未知身份 fail closed，未触发的普通 HTTP 保持原路由。

这些历史结果证明关键机制可以组合，但身份字段使用的是此前的 SPIFFE principal POC，UDP 也未使用本次新增的配置渲染器。它们不能替代当前 bundle 的端到端复验。

## 当前配置模型

唯一租户配置源是：

```text
tests/integration/agentio/testdata/multi-tenant-egress-poc/tenants.yaml
```

示例核心配置：

```yaml
tenants:
- id: tenant-a
  generation: 1
  mark: 40961
  workloads:
  - namespace: udp-hbone-poc
    name: udp-client-a
- id: tenant-b
  generation: 1
  mark: 40962
  workloads:
  - namespace: udp-hbone-poc
    name: udp-client-b
```

渲染出的关键关系为：

| downstream peer | route key | UDP cluster | mark |
| --- | --- | --- | --- |
| `udp-hbone-poc/udp-client-a` | `tenant-a-g1` | `poc_udp_tenant-a_g1` | 40961 |
| `udp-hbone-poc/udp-client-b` | `tenant-b-g1` | `poc_udp_tenant-b_g1` | 40962 |

Wasm plugin config 只包含 `{namespace, name, routeKey}` 和目标 MASQUE path，不包含 mark。mark 只出现在对应 HTTP/UDP cluster：

```yaml
upstream_bind_config:
  socket_options:
  - level: 1
    name: 36
    int_value: 40961
    state: STATE_PREBIND
```

## 本地验证命令与结果

在 2026-08-21 的当前工作树执行：

```bash
cargo test \
  --manifest-path tests/integration/agentio/testdata/multi-tenant-egress-poc/Cargo.toml
```

结果：

- 配置测试 9 个通过；
- request scope 测试 3 个通过；
- renderer 测试 4 个通过。

Wasm 构建：

```bash
cargo build \
  --manifest-path tests/integration/agentio/testdata/multi-tenant-egress-poc/Cargo.toml \
  --target wasm32-wasip1 \
  --release \
  --lib
```

结果：成功生成非空 `agentio_multi_tenant_egress_poc.wasm`。

使用真实 Wasm 渲染后：

- 外层 ConfigMap 加两份内嵌 EnvoyFilter，共 3 个 YAML 文档；
- 渲染文件约 506 KB；
- `kubectl apply --dry-run=client` 返回 `configmap/poc-multi-tenant-egress created (dry run)`；
- `udp-workloads.yaml` 中 3 个 ServiceAccount 和 3 个固定名称 Pod 均通过 client-side dry-run。

## Live POC 验证流程

完整命令、预期日志、xDS 查询、UDP 请求以及回滚步骤位于：

```text
tests/integration/agentio/testdata/multi-tenant-egress-poc/README.md
```

执行时必须按以下四层分别留证：

1. **源配置**：ConfigMap 中的 EnvoyFilter 内容与 `tenants.yaml` 一致；
2. **活动 xDS**：网关 config dump 中存在正确 filter 顺序、route、cluster 和 mark；
3. **运行时路由**：Wasm 日志显示 `namespace/name -> routeKey`，两个租户 cluster stats 分别增加；
4. **socket 权限与结果**：默认权限出现 `Setting 1/36 option on socket failed`，临时 NET_ADMIN 后两个 UDP echo 均成功，unknown identity 不产生 upstream activity。

只有四层全部满足，才能把当前可配置 UDP POC 标记为 live verified。

## 风险与生产化建议

- `downstream_peer.name` 在当前测试中是固定 Pod name；生产 Deployment/ReplicaSet Pod name 会变化。建议控制面把稳定 Sandbox UID、owner 或可信 label 投影成 tenant key。
- ConfigMap 渲染器适合 POC，不承担生产配置的版本冲突、状态回报、撤销排空和垃圾回收。生产方案应使用 CRD + KRT/controller。
- 每租户每服务一个 cluster 的规模为 `tenant × service`。需压测 xDS 体积、warming 时间、连接池数量和 UDP socket 数。
- 同一个 mark 不应在并存租户之间复用；回收 mark 前需等待旧 cluster/socket 和 conntrack 状态排空。
- `SO_MARK` 不是安全边界本身。必须验证 mark 对应的策略路由无法被 Pod 绕过，并将 VNI/VRF/出口凭证等隔离纳入威胁模型。
