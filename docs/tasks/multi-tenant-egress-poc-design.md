# 可配置多租户 Egress HTTP 与 UDP SO_MARK POC 设计

## 目标

在 `codex/udp-hbone-poc` 分支上提供一套可跟踪、可复现、可清理的 POC，验证 Agentio 出口网关能够根据可信的 `downstream_peer.namespace` 和 `downstream_peer.name` 识别租户，将 HTTP 和 CONNECT-UDP 流量送入租户独立的 Envoy cluster，并在该 cluster 创建的上游 socket 上设置租户专属 `SO_MARK`。

租户、workload 绑定、mark 和配置代际均来自 `tenants.yaml`，不编译进 Wasm。例如：

| 租户 | downstream peer | generation | SO_MARK |
| --- | --- | --- | --- |
| tenant-a | `udp-hbone-poc/udp-client-a` | 1 | `0xA001`（40961） |
| tenant-b | `udp-hbone-poc/udp-client-b` | 1 | `0xA002`（40962） |

未知、缺失或读取失败的 workload 身份必须 fail closed。

## 范围

本次只新增 POC 资产和验证文档：

- 通用 Rust Proxy-Wasm、配置解析和单元测试；
- 从 `tenants.yaml` 生成 ConfigMap/EnvoyFilter 的原生渲染器；
- tenant-a、tenant-b UDP 测试工作负载；
- 构建、下发、验证和清理说明；
- 已验证与待验证结果文档。

本次不修改 Agentio API、Go 控制面、Envoy 源码或现有 UDP/HBONE 实现，也不把 POC 行为默认开启到生产网关。

## 文件布局

```text
tests/integration/agentio/testdata/multi-tenant-egress-poc/
  Cargo.toml
  Cargo.lock
  tenants.yaml
  src/config.rs
  src/lib.rs
  src/bin/render.rs
  udp-workloads.yaml
  README.md

docs/tasks/
  multi-tenant-egress-poc-design.md
  validate-multi-tenant-egress-somark.md
```

POC bundle 位于现有 Agentio 集成测试数据目录下，但不接入默认 E2E runner，避免临时的 root/`NET_ADMIN` 验证改变标准测试场景。

## 配置与渲染

`tenants.yaml` 是唯一的租户配置来源：

```yaml
version: v1
configSourceNamespace: sandbox-traffic-system
httpGateway:
  namespace: sandbox-traffic-system
  name: egress-gateway
udpGateway:
  namespace: udp-hbone-poc
  name: waypoint
udpTarget:
  host: udp-echo.udp-hbone-poc.svc.cluster.local
  port: 9000
tenants:
- id: tenant-a
  generation: 1
  mark: 40961
  workloads:
  - namespace: sandbox
    name: client-v1
  - namespace: udp-hbone-poc
    name: udp-client-a
- id: tenant-b
  generation: 1
  mark: 40962
  workloads:
  - namespace: sandbox
    name: server-v1
  - namespace: udp-hbone-poc
    name: udp-client-b
```

渲染器读取配置和已经编译的 Wasm，并生成一个带 `manifests.agents.kruise.io/kube-source: "true"` 标签的 ConfigMap。ConfigMap 的 `sources` 中包含两个 EnvoyFilter：

- HTTP EnvoyFilter：目标为 `httpGateway`，生成租户 HTTP cluster、Wasm filter 和 route；
- UDP EnvoyFilter：目标为 `udpGateway`，生成租户 raw UDP cluster、Wasm filter 和 CONNECT-UDP route。

同一份租户绑定被序列化为 Wasm `plugin_configuration`，因此 Wasm 只实现通用身份查找，不包含租户常量。渲染前必须拒绝以下无效配置：

- 重复或不符合 DNS-label 子集的 tenant id；
- `generation=0`；
- `mark=0`、超出 `uint32` 或租户间重复；
- 空的 namespace/name；
- 同一个 `{namespace, name}` 被绑定到多个租户；
- 空 tenant 或空 workload 集合。

cluster 名包含 tenant id 和 generation，例如 `poc_udp_tenant-a_g1`。mark 变化时必须同时递增 generation，确保新配置使用新 cluster 和新 socket，而不复用旧连接池。

## 身份与路由数据流

Agentio waypoint 的 downstream metadata filter 将已认证对端 workload 信息写入 FilterState。Wasm 读取：

```text
filter_state["downstream_peer"].namespace
filter_state["downstream_peer"].name
```

Wasm 按以下顺序处理请求：

1. 删除调用方提供的内部租户路由 header；
2. 判断请求是显式 HTTP POC 请求还是 CONNECT-UDP；
3. 从 FilterState 读取 namespace 和 name；
4. 使用配置中的精确 `{namespace, name}` 映射到 route key；
5. 未知身份返回本地 403；
6. 写入仅供网关内部使用的租户 route key；
7. 调用 Envoy `clear_route_cache`；
8. 由重新计算后的 route 选择租户专属 cluster。

HTTP POC 继续使用显式触发 header 限制影响范围。CONNECT-UDP 由 `upgrade: connect-udp`、Capsule Protocol header 和固定 MASQUE path 识别，不依赖业务 Pod 注入租户 header。

## HTTP cluster

HTTP 为每个租户生成独立 dynamic-forward-proxy/TLS cluster：

```text
poc_http_tenant-a_g1_v4 -> SO_MARK 0xA001
poc_http_tenant-b_g1_v4 -> SO_MARK 0xA002
```

cluster 名不同，因此连接池不跨租户复用。它们可以共享 DNS cache，但不能共享 upstream connection pool。

## UDP cluster

CONNECT-UDP 终止后直接进入 raw UDP cluster。POC 为固定 UDP echo 服务生成每租户独立 cluster：

```text
poc_udp_tenant-a_g1 -> SO_MARK 0xA001
poc_udp_tenant-b_g1 -> SO_MARK 0xA002
```

每个 cluster 通过 `upstream_bind_config.socket_options` 配置：

```yaml
level: 1
name: 36
int_value: 40961 # 或 40962
state: STATE_PREBIND
```

`level=1/name=36` 对应 Linux `SOL_SOCKET/SO_MARK`。mark 在 UDP socket 创建和 connect 前设置。禁止在同一个共享 UDP socket 上按数据报切换 mark。

租户 CONNECT-UDP route 保留原服务 route 的 method、upgrade、Capsule Protocol 和 path 匹配条件，并额外匹配 Wasm 写入的内部租户 route key。它们必须插在原始共享 UDP route 之前。

## Filter 顺序

HTTP 转发链中的 Wasm 位于所有依赖 route 的 RBAC 之前。

CONNECT-UDP 的 Wasm 插在 `connect_authority` 之后、EPE/ext_proc 之前：

```text
connect_authority
poc_tenant_router
envoy.filters.http.ext_proc
envoy.filters.http.router
```

这样 Wasm 能读到可信 downstream peer，EPE 也能看到重新计算后的租户 route，而不是客户端最初命中的共享 route。

## 权限边界

Envoy 设置 `SO_MARK` 需要有效的 `CAP_NET_ADMIN`。仅在 PodSpec 中添加 capability 但 Envoy 进程的 `CapEff` 为 0 时，`setsockopt` 仍会失败。

POC 文档包含两阶段验证：

1. 默认权限下请求失败，并记录 `Setting 1/36 option on socket failed`，证明 Envoy 确实尝试设置 mark；
2. 临时将 POC 网关设置为 root 且仅增加 `NET_ADMIN` 后，请求成功，并确认 Envoy `CapEff` 包含该 capability。

该安全上下文只允许用于测试，验证结束必须恢复原值。POC bundle 不会自动修改网关 Deployment。

## 验证矩阵

### 配置与本地渲染

- 合法配置可生成稳定的 route key、HTTP/UDP cluster 名和 `plugin_configuration`；
- 重复 tenant、mark、workload 绑定和非法 generation 均被拒绝；
- 修改 mark 且递增 generation 后，cluster 名同步变化；
- Wasm 原生单元测试通过；
- Wasm release 构建成功；
- 生成的 ConfigMap 可被 YAML 解析并通过 client-side dry-run。

### HTTP 验证

- tenant-a 伪造 tenant-b route，最终仍进入 tenant-a cluster；
- tenant-b 伪造 tenant-a route，最终仍进入 tenant-b cluster；
- 未知 downstream peer 本地 403；
- 不带触发条件的普通 HTTP 流量保持默认路由。

### UDP 验证

- tenant-a UDP client 命中 `poc_udp_tenant-a_g1` 并收到 echo；
- tenant-b UDP client 命中 `poc_udp_tenant-b_g1` 并收到 echo；
- Wasm 日志记录 namespace/name 和租户决定；
- xDS 和 cluster 统计分别证明两个 UDP cluster 被使用；
- 未知 downstream peer 不创建 upstream UDP socket，并 fail closed。

外部 HTTP 目标的业务状态码不作为路由成功判据。UDP 以 echo 内容、route/cluster 统计和 Wasm 日志联合判断。

## 清理

清理只删除 POC 创建的对象并恢复临时安全上下文：

1. 删除 POC ConfigMap；
2. 删除 tenant-a、tenant-b 测试 Pod 和 ServiceAccount；
3. 恢复网关原始 securityContext；
4. 条件轮询直至 POC filter、route、cluster 全部从活动 xDS 消失；
5. 确认网关 Ready、无额外重启并且默认出口正常。

静态 route 的移除可能晚于 filter 和 cluster，因此不能在删除后用单次查询判定清理失败。

## 生产化边界

- POC 直接绑定 Pod name；Deployment/ReplicaSet 生成的 Pod name 会变化。生产映射应使用稳定的 Sandbox UID、owner、label 或由控制面生成的身份键。
- 生产配置应由 CRD/KRT/controller 管理，而不是由手工 ConfigMap 渲染器承担一致性和回收。
- 生产 cluster key 至少包含 `{tenant_id, service, generation}`，避免回收后复用旧 socket。
- 每租户每服务 cluster 的规模是 `tenant × service`，需要单独评估 xDS 大小和收敛时间。
- `SO_MARK` 只完成路由选择标记，不等于完整租户隔离；仍需验证 `ip rule`、路由表、conntrack zone、VRF/VXLAN/VNI 和最终出口。
- UDP/DNS/ICMP 的协议、配额、MTU、ICMP 错误传播与撤销排空需要分别验证。
