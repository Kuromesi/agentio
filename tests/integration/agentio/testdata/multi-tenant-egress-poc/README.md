# 可配置多租户 Egress SO_MARK POC

这套 POC 使用 `downstream_peer.namespace/name` 将请求映射到租户独立的 HTTP/UDP cluster。租户、workload 绑定、generation 和 `SO_MARK` 均由 `tenants.yaml` 提供；Wasm 不包含固定租户。

POC 不接入默认 E2E，所有集群变更都需要人工执行。完整设计和验证边界见：

- `docs/tasks/multi-tenant-egress-poc-design.md`
- `docs/tasks/validate-multi-tenant-egress-somark.md`

## 1. 配置约束

编辑 `tenants.yaml` 时遵守以下约束：

- tenant id 只使用小写字母、数字和中划线，并以字母或数字开头/结尾；
- tenant id、mark 和 `{namespace, name}` 绑定均不能重复；
- `mark` 和 `generation` 必须大于 0；
- mark 变化时必须递增 generation；
- 当前 POC 精确匹配 Pod name，因此测试 Pod 使用固定名称。生产环境不能直接依赖 Deployment 生成的 Pod name。

tenant-a、tenant-b 使用独立 ServiceAccount，方便同时观察 SPIFFE 身份；当前 route 决策只读取 downstream peer 的 namespace/name。

## 2. 本地构建与渲染

在仓库根目录执行：

```bash
export POC_DIR=tests/integration/agentio/testdata/multi-tenant-egress-poc

cargo test --manifest-path "$POC_DIR/Cargo.toml"
cargo build \
  --manifest-path "$POC_DIR/Cargo.toml" \
  --target wasm32-wasip1 \
  --release \
  --lib

mkdir -p "$POC_DIR/out"
cargo run \
  --manifest-path "$POC_DIR/Cargo.toml" \
  --bin render -- \
  "$POC_DIR/tenants.yaml" \
  "$POC_DIR/target/wasm32-wasip1/release/agentio_multi_tenant_egress_poc.wasm" \
  "$POC_DIR/out/poc-multi-tenant-egress.yaml"

kubectl apply --dry-run=client \
  -f "$POC_DIR/out/poc-multi-tenant-egress.yaml"
```

渲染结果是 `sandbox-traffic-system/poc-multi-tenant-egress` ConfigMap，`data.sources` 内含分别目标到 HTTP 和 UDP Gateway 的 EnvoyFilter。

## 3. 准备 UDP POC

以下命令会改变 `cluster-1VOH82`。先确认目标，再逐项执行：

```bash
export POC_KUBECONFIG=/Users/kuromesi/.kube/my-config/cluster-1VOH82
export POC_DIR=tests/integration/agentio/testdata/multi-tenant-egress-poc

kubectl --kubeconfig "$POC_KUBECONFIG" apply \
  -f tests/integration/agentio/testdata/udp-hbone-poc.yaml
kubectl --kubeconfig "$POC_KUBECONFIG" apply \
  -f "$POC_DIR/udp-workloads.yaml"
kubectl --kubeconfig "$POC_KUBECONFIG" apply \
  -f "$POC_DIR/out/poc-multi-tenant-egress.yaml"

kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc wait \
  --for=condition=Ready pod/udp-client-a pod/udp-client-b pod/udp-client-unknown \
  --timeout=180s
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc rollout status \
  deployment/waypoint --timeout=180s
```

如果基础 `udp-hbone-poc.yaml` 使用的 `localhost:5000/proxy-init:istio-testing` 不存在，应先按该分支原有 UDP/HBONE POC 流程构建并加载镜像，不能改用未经验证的 proxy-init。

## 4. 验证渲染配置与活动 xDS

先验证 ConfigMap 源已被控制面接受。以下命令只读取网关状态：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  deployment/waypoint -c istio-proxy -- \
  pilot-agent request GET config_dump > /tmp/poc-waypoint-config-dump.json

jq '[
  .configs[]
  | select(."@type" == "type.googleapis.com/envoy.admin.v3.ClustersConfigDump")
  | .dynamic_active_clusters[]
  | .cluster
  | select(.name | startswith("poc_udp_"))
  | {
      name,
      mark: .upstream_bind_config.socket_options[0].int_value,
      level: .upstream_bind_config.socket_options[0].level,
      option: .upstream_bind_config.socket_options[0].name
    }
]' /tmp/poc-waypoint-config-dump.json
```

期望至少包含：

```text
poc_udp_tenant-a_g1 mark=40961 level=1 option=36
poc_udp_tenant-b_g1 mark=40962 level=1 option=36
```

继续检查：

- `connect_terminate` 的 HTTP filter 顺序为 `connect_authority`、`poc_tenant_router`、EPE/ext_proc、router；
- route `poc-connect-udp-tenant-a-g1` 和 `poc-connect-udp-tenant-b-g1` 位于原始共享 route 前；
- 两条 route 的 cluster、MASQUE path、method、upgrade 和 Capsule Protocol 均与渲染结果一致；
- 网关日志无 Wasm 启动、EnvoyFilter 解析或 warming 失败。

只看到源码或 ConfigMap 不代表 xDS 已接受；只看到 xDS 也不代表 runtime 已使用对应 cluster。

## 5. 默认权限下证明 Envoy 尝试设置 mark

先记录网关实际 capability：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  deployment/waypoint -c istio-proxy -- \
  sh -c 'grep "^CapEff:" /proc/1/status'
```

发送 tenant-a UDP：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  pod/udp-client-a -c client -- \
  sh -c 'printf "tenant-a\n" | socat -T 5 - UDP4-DATAGRAM:udp-echo.udp-hbone-poc.svc.cluster.local:9000'
```

若网关无 `CAP_NET_ADMIN`，期望请求失败且日志出现类似：

```text
Setting 1/36 option on socket failed
```

这只证明 Envoy 尝试在目标 socket 上设置 `SO_MARK`，尚未证明 UDP echo 成功。

## 6. 临时增加 NET_ADMIN 后验证两个租户

仅 POC 可执行以下变更。`kubectl patch` 会产生一个新的 Deployment revision，清理时必须 `rollout undo`：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc patch \
  deployment/waypoint --type=strategic -p '
spec:
  template:
    spec:
      containers:
      - name: istio-proxy
        securityContext:
          runAsUser: 0
          runAsNonRoot: false
          allowPrivilegeEscalation: false
          capabilities:
            add: [NET_ADMIN]
'

kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc rollout status \
  deployment/waypoint --timeout=180s
```

确认 `CapEff` 后分别发送流量：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  pod/udp-client-a -c client -- \
  sh -c 'printf "tenant-a\n" | socat -T 5 - UDP4-DATAGRAM:udp-echo.udp-hbone-poc.svc.cluster.local:9000'

kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  pod/udp-client-b -c client -- \
  sh -c 'printf "tenant-b\n" | socat -T 5 - UDP4-DATAGRAM:udp-echo.udp-hbone-poc.svc.cluster.local:9000'
```

期望返回各自原文。网关日志必须分别出现：

```text
POC_TENANT_ROUTER namespace=udp-hbone-poc name=udp-client-a route=tenant-a-g1
POC_TENANT_ROUTER namespace=udp-hbone-poc name=udp-client-b route=tenant-b-g1
```

同时读取 stats，确认两个 cluster 均产生独立 activity：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  deployment/waypoint -c istio-proxy -- \
  pilot-agent request GET 'stats?filter=poc_udp_'
```

## 7. 未知身份 fail closed

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc exec \
  pod/udp-client-unknown -c client -- \
  sh -c 'printf "unknown\n" | socat -T 5 - UDP4-DATAGRAM:udp-echo.udp-hbone-poc.svc.cluster.local:9000'
```

客户端预期超时或失败；网关日志应记录：

```text
POC_TENANT_ROUTER namespace=udp-hbone-poc name=udp-client-unknown decision=deny
```

tenant-a/tenant-b cluster 的 activity 不应因该请求增加。

## 8. 可选 HTTP 回归

示例配置把 `sandbox/client-v1` 和 `sandbox/server-v1` 分别绑定到 tenant-a/tenant-b。HTTP POC 只处理带显式触发 header 的请求：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n sandbox exec client-v1 -c app -- \
  curl -ksS -D - -o /dev/null --max-time 15 \
  -H 'x-agentio-poc-tenant: 1' \
  -H 'x-agentio-poc-route: tenant-b-g1' \
  https://www.aliyun.com/
```

期望 response header 为 `x-agentio-poc-cluster: tenant-a`；客户端伪造的内部 route 被 Wasm 删除并重算。不带 `x-agentio-poc-tenant: 1` 的 HTTP 请求必须继续使用默认路由。

## 9. 清理

先恢复被临时修改的 waypoint，再删除 POC 对象：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc rollout undo \
  deployment/waypoint
kubectl --kubeconfig "$POC_KUBECONFIG" -n udp-hbone-poc rollout status \
  deployment/waypoint --timeout=180s

kubectl --kubeconfig "$POC_KUBECONFIG" delete \
  -f "$POC_DIR/out/poc-multi-tenant-egress.yaml" --ignore-not-found
kubectl --kubeconfig "$POC_KUBECONFIG" delete \
  -f "$POC_DIR/udp-workloads.yaml" --ignore-not-found
```

如果该 namespace 仅用于本 POC，再删除基础资源：

```bash
kubectl --kubeconfig "$POC_KUBECONFIG" delete \
  -f tests/integration/agentio/testdata/udp-hbone-poc.yaml --ignore-not-found
```

最后条件轮询，直到 `poc_tenant_router`、`poc_http_`、`poc_udp_` 和 `poc-connect-udp-` 均从活动 xDS 消失。静态 route 的移除可能晚于 filter 和 cluster，不能以一次 config dump 作为清理失败结论。
