# 使用 Agentio Ambient ztunnel 管理 Substrate Actor 出口流量

本文介绍如何在已部署 Agent Substrate 的 Kubernetes 集群中，以 Ambient 模式部署 Agentio，并使用节点级 ztunnel 接管 Actor 经 Worker 发出的 TCP 出口流量。文档同时覆盖 `PASSTHROUGH`、定向 `DENY`、出口网关 `GATEWAY` 和 `TrafficPolicy` 的配置与验证。

> 本文重点是 Substrate Actor，而不是普通 Kubernetes Pod。相关链路先后于 2026-08-17 在 `kind-substrate-poc`、2026-08-24 在 ACK `substrate-network` 集群完成 PoC。后一次验证覆盖 Microsandbox、ListWorkers ActorContext、节点级 ztunnel、Gateway API 出口网关、TrafficPolicy 和 EPE SecurityProfile。

## 1. 结论与适用边界

Agentio Ambient 模式可以接管 Substrate Actor 的出口流量，但必须先区分 Worker 的网络实现：

- gVisor Worker 使用独立的 `ateom0` 时，可以直接配置 `istio.io/reroute-virtual-interfaces: ateom0`。
- 2026-08-24 实测的 Microsandbox Worker 使用 `br-msb` 和 `msb-tap*`。Actor 包从 `msb-tap*` 进入 Linux bridge，但 L3 netfilter 看到的逻辑入接口是 `br-msb`。直接把 `br-msb` 配成 reroute 接口会把 Worker 正常入向流量也误判为出向流量，不能作为正式配置。
- Agentio CNI PoC 分支已经支持 Pod 注解 `agentio.io/reroute-bridge-port-prefixes: msb-tap`。CNI 会使用 `physdev --physdev-in msb-tap+` 只识别 Actor TAP 入包并重定向到 `15001`；Worker Pod 重建后由 CNI 自动恢复，不再需要手工写入这两条 `physdev` 规则。
- Worker 中 atunnel 的出口监听端口不能继续使用 `15001`，因为该端口由 Ambient ztunnel 使用。PoC 使用 `127.0.0.1:15099`。
- Worker 不再注入 Agentio ztunnel sidecar，避免 sidecar 与 Ambient 重复拦截。
- Agentio CNI 和节点级 ztunnel 正常运行，且 CNI 已同时为 Worker Pod 编程 `ateom0` 和 `msb-tap*` 入流量规则。

已有 PoC 证据和本文需要复测的验收项如下：

| 场景 | PoC 状态 | 验收结果 |
| --- | --- | --- |
| 默认 `PASSTHROUGH` | 已在 Ambient Actor 链路实测 | Actor 访问目标服务返回 HTTP 200 |
| 指定目标 `DENY` | 已在 Ambient Actor 链路实测 | 同一目标返回 HTTP 502 或连接错误；ztunnel 日志显示被出口策略拒绝 |
| 恢复 `PASSTHROUGH` | 已在 Ambient Actor 链路实测 | 新连接再次返回 HTTP 200 |
| 指定目标 `GATEWAY` | 已在 ACK Microsandbox Ambient Actor 链路实测 | 流量经过 Agentio 出口网关；目标端看到的来源地址变为网关 Pod 地址 |
| `TrafficPolicy` 出向拒绝 | 已在 ACK Microsandbox Ambient Actor 链路实测 | 被 Worker Pod label 选中的目标返回 502，ztunnel 记录明确拒绝 |
| `TrafficPolicy` 入向拒绝 | 已在 ACK Microsandbox Ambient Actor 链路完成 selector A/B | selector 不匹配为 400，匹配后为 503，ztunnel 记录明确拒绝 |
| Actor 级 `SecurityProfile` | 已使用 `kruise.io/actor-name` 实测 | 普通路径返回 200，命中路径返回 453，且 Worker Pod 本身没有 Actor name label |

Ambient 实测的核心证据为：gVisor 链路的 `ateom0 -> 15001` 和 Microsandbox 链路的 `physdev msb-tap+ -> 15001` counter 都会随 Actor 新连接增长。2026-08-24 的 CNI 重建复测中，Worker UID 从 `53cc01f8-f01f-4b7d-8cc7-73535d45997a` 变为 `c43f4c85-f811-4238-809b-9625758d130b` 后，CNI 在 clean-state netns 中自动生成规则；第二个 Worker 上的 counter 从 0 增长到 5。拒绝阶段存在 ztunnel 的策略拒绝日志；GATEWAY 请求的后端来源地址为 Gateway Pod；EPE 能按 ActorContext 中的 `kruise.io/actor-name` 命中策略。

`egressPolicies` 和 `TrafficPolicy` 的选择边界仍是 **Worker workload**；Actor 级七层选择由 ListWorkers assignment 派生的 `Workload.extensions["actor-context"]` 和 EPE `SecurityProfile` 完成。当前只适用于一个 Worker 同时绑定一个 Actor。多个 Actor 共用同一 Worker netns 时，仍需要可靠的“连接 -> ActorContext”绑定。

## 2. 数据路径和组件职责

Actor 出口请求的实际路径如下：

```text
Actor gVisor 网络命名空间
  eth0: 169.254.17.2
        |
        v
Worker Pod 网络命名空间
  ateom0: 169.254.17.1
        |
        | CNI 在 PREROUTING 中匹配 -i ateom0
        v
  REDIRECT -> 15001
        |
        | Worker netns 中由 ztunnel 创建的监听 socket
        v
节点级 Agentio ztunnel 进程
        |
        | egressPolicies / TrafficPolicy / GATEWAY
        v
目标服务或 Agentio 出口网关
```

以上是具有独立 `ateom0` 的 gVisor Worker。2026-08-24 ACK Microsandbox 的实际路径不同：

```text
Actor MicroVM
  eth0: 169.254.0.21
        |
        v
Worker Pod netns
  msb-tap1 -> br-msb: 169.254.0.22
        |
        | bridge physical ingress = msb-tap1
        | L3 logical ingress = br-msb
        | Agentio CNI: physdev --physdev-in msb-tap+ -> REDIRECT 15001
        v
Agentio node ztunnel
        |
        +-- PASSTHROUGH / TrafficPolicy
        |
        +-- HBONE -> Gateway API agentio-egress -> EPE -> upstream
```

不要直接为 Microsandbox 配置 `istio.io/reroute-virtual-interfaces: br-msb`。Worker Pod IP 也挂在 `br-msb` 上，这会把 atenet-router 到 Worker 的正常入向连接重定向到 ztunnel 出向 listener，导致入向/出向语义混淆。请在 Worker Pod 模板中配置前缀，不要填写 `+` 或 `*`：

```yaml
metadata:
  annotations:
    agentio.io/reroute-bridge-port-prefixes: msb-tap
```

Agentio CNI 会在 iptables 后端生成以下等价规则：

```bash
iptables -t nat -I ISTIO_PRERT 1 \
  -m physdev --physdev-in 'msb-tap+' -p tcp -j RETURN
iptables -t nat -I ISTIO_PRERT 1 \
  -m physdev --physdev-in 'msb-tap+' -p tcp \
  -j REDIRECT --to-ports 15001
```

最终顺序是 `REDIRECT` 在前、`RETURN` 在后。`physdev` 能看到 bridge 的物理入端口，既能捕获 Actor TAP 流量，又不会把从 Worker `eth0` 进入的普通入向连接误判为 Actor 出向流量。使用原生 nftables 后端时，CNI 生成等价的 `meta sdifname "msb-tap*" meta l4proto tcp redirect to :15001` 和 `return` 规则。

ztunnel 进程运行在节点级 DaemonSet 中，但这不表示流量要先离开 Worker Pod 再进入 ztunnel Pod。当前 Agentio 实现中，CNI node agent 是 ZDS Unix socket server，ztunnel 是连接该 socket 的 client。CNI 发现 Worker Pod netns 后，通过 ZDS `AddWorkload` 把 netns FD 发送给 ztunnel；ztunnel 随后进入该 Worker 网络命名空间，创建 `15001`、`15006` 和 `15008` 等监听 socket。因此，Worker 内的重定向规则可以直接把 `ateom0` 流量送入 ztunnel。

各组件的职责为：

- **Substrate atunnel**：负责 Actor 与 Worker 之间的网络隧道及 Actor 网络接入。
- **Agentio CNI**：识别加入 Ambient 的 Worker，为 `ateom0` 或匹配 `msb-tap*` 的 bridge 物理端口编程重定向规则，并把 Worker netns 交给 ztunnel。
- **Agentio ztunnel**：在 Worker netns 中接收被重定向的 TCP 连接，执行四层出口策略，并按需直连或转发到出口网关。
- **agentiod**：生成 ztunnel 所需的 workload、证书、出口策略和 TrafficPolicy 配置。
- **Agentio 出口网关**：承接 `GATEWAY` 流量；需要七层检查时，还可以在网关侧接 EPE/ext-proc。

## 3. 前提条件

准备以下环境和权限：

- 已运行的 Agent Substrate 集群，且 Actor 可以被调度到目标 Worker。
- Kubernetes 集群管理员权限。
- Linux 工作节点，允许 Agentio CNI、ztunnel 使用所需的 hostPath、网络命名空间和 Linux capabilities。
- 集群原有 CNI 支持链式执行，或者已经按 Agentio Chart 要求部署 Agentio CNI。
- `kubectl`、Helm 3、`jq`，以及与当前 Substrate 版本匹配的 `kubectl-ate`。
- 可被集群拉取的 Agentio control plane、CNI、ztunnel 和可选 gateway 镜像。
- 一个位于测试环境中的目标 HTTP/TCP 服务。不要直接用生产服务测试拒绝策略。

建议先在独立集群或独立 WorkerPool 上验证。修改已有 Worker Deployment 时，Substrate controller 可能把手工修改恢复成其声明状态；正式部署应把标签、注解和 atunnel 参数写入 Worker 模板或对应 controller 的期望配置。

本文命令使用以下变量：

```bash
export KUBECONFIG=/path/to/substrate-kubeconfig
export AGENTIO_CHART=/path/to/agentio/manifests/charts/agentio
export AGENTIO_BASE_VALUES=/path/to/your-agentio-values.yaml

export AGENTIO_NAMESPACE=agentio-system
export WORKER_NAMESPACE=ate-demo-egress
export WORKER_DEPLOYMENT=egress
export WORKER_POOL_LABEL=egress

export TARGET_IP=10.96.35.182
export TARGET_PORT=80
```

`AGENTIO_BASE_VALUES` 应包含当前环境的镜像仓库、固定镜像版本、CA 和其他基础配置。不要在正式环境依赖 Chart 的 `latest` 默认标签。

## 4. 部署 Agentio Ambient

### 4.1 准备 Ambient 覆盖配置

创建 `/tmp/agentio-ambient-values.yaml`：

```yaml
global:
  enableFirewallRules: true
  meshInternalTrafficPolicy: PASSTHROUGH

# 纯 Ambient PoC 可以全局关闭 sidecar 注入。
# 如果同一集群还有其他 sidecar workload，可以保留 true，
# 但必须在 Substrate Worker 上单独设置 sidecar.istio.io/inject: "false"。
sidecarInjector:
  enabled: false

ambient:
  enabled: true
  cni:
    chained: true
    dnsCapture: true
  ztunnel:
    env:
      FIREWALL_BACKEND: iptables
```

说明：

- `ambient.enabled=true` 会部署 `agentio-cni-node` 和节点级 `ztunnel` DaemonSet。
- `global.enableFirewallRules=true` 允许 Agentio 为捕获到的 workload 设置重定向规则。
- 初次接入时建议使用 `meshInternalTrafficPolicy=PASSTHROUGH`，先证明基础链路，再逐步增加拒绝规则。
- 如果节点默认使用 nftables，可保留 ztunnel 自动探测，或者把 `FIREWALL_BACKEND` 改为经当前环境验证的后端。后续检查必须使用与实际后端一致的命令。

如果基础 values 尚未固定 CNI 和 ztunnel 镜像，可在覆盖文件中显式设置：

```yaml
ambient:
  cni:
    image:
      hub: registry.example.com/agentio
      name: install-cni
      tag: v1.0.0

ztunnel:
  image:
    hub: registry.example.com/agentio
    name: ztunnel
    tag: v1.0.0
```

请将以上地址和版本替换为实际发布产物；CNI 与 ztunnel 不一定和 agentiod 使用同一个构建来源或版本节奏。

### 4.2 安装或升级

```bash
helm upgrade --install agentio "$AGENTIO_CHART" \
  --kubeconfig "$KUBECONFIG" \
  --namespace "$AGENTIO_NAMESPACE" \
  --create-namespace \
  --values "$AGENTIO_BASE_VALUES" \
  --values /tmp/agentio-ambient-values.yaml \
  --wait \
  --timeout 5m
```

检查组件：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  rollout status daemonset/agentio-cni-node --timeout=5m

kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  rollout status daemonset/ztunnel --timeout=5m

kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  get pod -o wide
```

## 5. 将 Substrate Worker 接入 Ambient

### 5.1 配置 Worker Pod 模板

Worker Pod 模板至少需要以下字段：

```yaml
metadata:
  labels:
    ate.dev/worker-pool: egress
    istio.io/dataplane-mode: ambient
  annotations:
    sidecar.istio.io/inject: "false"
    istio.io/reroute-virtual-interfaces: ateom0
    agentio.io/reroute-bridge-port-prefixes: msb-tap
    ambient.istio.io/dns-capture: "false"
spec:
  containers:
  - name: ateom
    args:
    - --atunnel-egress-listen-address=127.0.0.1:15099
```

其中：

- `istio.io/dataplane-mode: ambient` 使 CNI 选择该 Worker。
- `istio.io/reroute-virtual-interfaces: ateom0` 告诉 CNI 捕获经 `ateom0` 进入 Worker netns 的 Actor 流量。
- `agentio.io/reroute-bridge-port-prefixes: msb-tap` 告诉 Agentio CNI 捕获经 `msb-tap*` 进入 bridge 的 Microsandbox Actor 流量。该值是接口名前缀，不包含通配符；多个前缀使用逗号分隔。
- `sidecar.istio.io/inject: "false"` 防止同时注入 ztunnel sidecar。
- `ambient.istio.io/dns-capture: "false"` 在第一阶段关闭 DNS 捕获，避免把 DNS 变量混入 TCP 出口 PoC；确认基础链路后再单独验证 DNS。
- `--atunnel-egress-listen-address=127.0.0.1:15099` 释放 `15001` 给 Ambient ztunnel。

不要同时配置 sidecar 模式使用的 `traffic.sidecar.istio.io/kubevirtInterfaces: ateom0`。该注解属于 sidecar 方案，Ambient 使用的是 `istio.io/reroute-virtual-interfaces`。

### 5.2 PoC 环境临时修改现有 Deployment

正式方案应修改 WorkerPool 的声明配置。只有在 controller 暂时无法表达上述字段时，才在隔离的 PoC 环境直接修改 Deployment。

先保存当前状态，并确认哪个 controller 管理该 Deployment：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  get deployment "$WORKER_DEPLOYMENT" -o yaml \
  > "/tmp/${WORKER_DEPLOYMENT}-before-ambient.yaml"

kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  get deployment "$WORKER_DEPLOYMENT" \
  -o jsonpath='{.metadata.ownerReferences}{"\n"}'
```

如果管理 controller 会持续回写，可在确认影响范围后临时暂停对应 controller。记录原副本数，验证结束后恢复。不要在共享或生产集群执行此操作。

创建 `/tmp/worker-ambient-patch.yaml`：

```yaml
spec:
  template:
    metadata:
      labels:
        istio.io/dataplane-mode: ambient
      annotations:
        sidecar.istio.io/inject: "false"
        istio.io/reroute-virtual-interfaces: ateom0
        agentio.io/reroute-bridge-port-prefixes: msb-tap
        ambient.istio.io/dns-capture: "false"
```

应用 Pod 模板修改：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  patch deployment "$WORKER_DEPLOYMENT" \
  --type=merge \
  --patch-file /tmp/worker-ambient-patch.yaml
```

如果 ateom 仍占用 `15001`，先定位容器及参数下标，再做精确 JSON Patch：

```bash
export ATEOM_CONTAINER_INDEX=$(
  kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
    get deployment "$WORKER_DEPLOYMENT" -o json \
  | jq -r '.spec.template.spec.containers | to_entries[] |
      select(.value.name == "ateom") | .key'
)

test -n "$ATEOM_CONTAINER_INDEX"

export ATUNNEL_ARG_INDEX=$(
  kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
    get deployment "$WORKER_DEPLOYMENT" -o json \
  | jq -r --argjson container "$ATEOM_CONTAINER_INDEX" '
      .spec.template.spec.containers[$container].args | to_entries[] |
      select(.value | startswith("--atunnel-egress-listen-address=")) | .key'
)

test -n "$ATUNNEL_ARG_INDEX"

kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  patch deployment "$WORKER_DEPLOYMENT" --type=json \
  -p="[{
    \"op\": \"replace\",
    \"path\": \"/spec/template/spec/containers/${ATEOM_CONTAINER_INDEX}/args/${ATUNNEL_ARG_INDEX}\",
    \"value\": \"--atunnel-egress-listen-address=127.0.0.1:15099\"
  }]"
```

如果命令找不到旧参数，应停止并检查 ateom 的实际参数，不要猜测数组下标，也不要盲目新增重复参数。

等待新 Worker Pod 就绪：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  rollout status deployment/"$WORKER_DEPLOYMENT" --timeout=5m

kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  get pod -l "ate.dev/worker-pool=${WORKER_POOL_LABEL}" \
  -o custom-columns='NAME:.metadata.name,CONTAINERS:.spec.containers[*].name,INIT:.spec.initContainers[*].name'
```

结果中不应出现 Agentio ztunnel sidecar 或 `istio-init`。修改标签和注解后应重新创建 Worker Pod，让 CNI 从 Pod 创建阶段完成纳管。

## 6. 验证 Worker 已被 Ambient 纳管

获取一个 Worker Pod：

```bash
export WORKER_POD=$(
  kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
    get pod -l "ate.dev/worker-pool=${WORKER_POOL_LABEL}" \
    -o jsonpath='{.items[0].metadata.name}'
)
```

检查 CNI 写入的纳管状态：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  get pod "$WORKER_POD" \
  -o jsonpath='{.metadata.annotations.ambient\.istio\.io/redirection}{"\n"}'
```

期望输出：

```text
enabled
```

检查 ztunnel 日志中是否发现该 workload：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  logs -l app=ztunnel --all-containers=true --prefix=true --since=10m \
  | grep -F "$WORKER_POD"
```

### 6.1 Kind 环境的 netns 深度检查

下面的命令是 Kind 专用证据检查。普通托管 Kubernetes 集群需要使用对应节点运行时和节点调试方式。

```bash
export WORKER_NODE=$(
  kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
    get pod "$WORKER_POD" -o jsonpath='{.spec.nodeName}'
)

export POD_SANDBOX_ID=$(
  docker exec "$WORKER_NODE" crictl pods --name "$WORKER_POD" -q | head -1
)

export WORKER_NETNS_PID=$(
  docker exec "$WORKER_NODE" crictl inspectp "$POD_SANDBOX_ID" | jq -r '.info.pid'
)

docker exec "$WORKER_NODE" \
  nsenter -t "$WORKER_NETNS_PID" -n ip -br address

docker exec "$WORKER_NODE" \
  nsenter -t "$WORKER_NETNS_PID" -n ss -lntp
```

应看到：

- `ateom0` 地址通常为 `169.254.17.1`。
- atunnel/ateom 监听 `127.0.0.1:15099`。
- ztunnel 在 Worker netns 中监听 `15001`，并通常监听入向端口 `15006`、`15008`。

先确认节点使用的 iptables 后端：

```bash
docker exec "$WORKER_NODE" \
  nsenter -t "$WORKER_NETNS_PID" -n iptables --version
```

PoC 集群使用 legacy 后端，检查命令为：

```bash
docker exec "$WORKER_NODE" \
  nsenter -t "$WORKER_NETNS_PID" -n iptables-legacy-save -t nat \
  | grep -E 'ISTIO_PRERT|ateom0|15001'
```

期望存在与下列语义等价的规则：

```text
-A ISTIO_PRERT -i ateom0 -p tcp -j REDIRECT --to-ports 15001
```

如果节点使用 nft 后端，改用 `iptables-nft-save`。后续可比较该规则的 packet counter，证明 Actor 请求确实命中 `ateom0 -> 15001`。

## 7. 创建 Actor 并建立基线流量

确保 Actor 模板会把 Actor 分配到刚刚纳管的 Worker。以下命令来自 PoC 环境；不同版本的 `kubectl-ate` 参数可能略有差异：

```bash
/path/to/kubectl-ate create actor ambient-ztunnel-poc \
  -a agentio-poc \
  --template "${WORKER_NAMESPACE}/${WORKER_POOL_LABEL}" \
  --kubeconfig "$KUBECONFIG"

/path/to/kubectl-ate resume actor ambient-ztunnel-poc \
  -a agentio-poc \
  --kubeconfig "$KUBECONFIG"
```

在发送流量前，确认 Actor 处于 Ready，并确认承载它的 Worker 是 `$WORKER_POD`。如果 Actor 仍处于 `RESUMING`，先排查 Worker 到 Actor 的 readyz/checkpoint 链路，不要把生命周期问题误判为 ztunnel 拒绝。

如果 Actor 的 HTTP 入口由 atenet-router 暴露，可以建立本地转发：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n ate-system \
  port-forward service/atenet-router 18124:80
```

另开终端，触发 Actor 访问目标服务：

```bash
curl -sS -X POST http://127.0.0.1:18124/ \
  -H 'Host: ambient-ztunnel-poc.agentio-poc.actors.resources.substrate.ate.dev' \
  -H 'Content-Type: application/json' \
  --data "{\"url\":\"http://${TARGET_IP}:${TARGET_PORT}/ambient-baseline\"}"
```

基线请求应返回 HTTP 200。随后检查 ztunnel 日志：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  logs -l app=ztunnel --all-containers=true --prefix=true --since=5m \
  | grep -E "169\.254\.17\.2|${TARGET_IP}:${TARGET_PORT}|direction=outbound"
```

PoC 中可观察到的关键字段为：

```text
src.addr=169.254.17.2
src.workload=Worker Pod 对应的 workload 名称
src.namespace=ate-demo-egress
dst.addr=10.96.35.182:80
direction=outbound
```

这里的 `src.addr` 是 Actor 虚拟地址，但 workload 身份仍解析为承载它的 Worker。

## 8. 使用 egressPolicies 管理出口流量

`egressPolicies` 是有顺序的，按首条匹配规则执行。建议始终保留命名空间级和全局的 `PASSTHROUGH` 兜底，避免误伤 Worker 内部流量。

在升级前先检查实际生效配置。`agentio-config-primary` 如果存在，会覆盖同名基础配置；Helm 的列表值也通常是整体替换，不是逐项合并：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  get configmap agentio-config -o yaml

kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  get configmap agentio-config-primary -o yaml 2>/dev/null || true
```

### 8.1 定向拒绝一个目标

创建 `/tmp/agentio-egress-deny-values.yaml`：

```yaml
egressPolicies:
- namespaces:
  - ate-demo-egress
  matchCidrs:
  - 10.96.35.182/32
  matchPorts:
  - "80"
  policy: DENY
- namespaces:
  - ate-demo-egress
  policy: PASSTHROUGH
- policy: PASSTHROUGH
```

将示例命名空间、CIDR 和端口改为 `$WORKER_NAMESPACE`、`$TARGET_IP/32` 和 `$TARGET_PORT` 的实际值，然后升级：

```bash
helm upgrade agentio "$AGENTIO_CHART" \
  --kubeconfig "$KUBECONFIG" \
  --namespace "$AGENTIO_NAMESPACE" \
  --reuse-values \
  --values /tmp/agentio-egress-deny-values.yaml \
  --wait \
  --timeout 5m
```

使用新连接再次请求目标。期望 Actor 返回 HTTP 502、EOF 或明确的连接错误，ztunnel 日志中出现 `denied by egress policy`，并包含原始目标地址：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  logs -l app=ztunnel --all-containers=true --prefix=true --since=5m \
  | grep -E "denied by egress policy|${TARGET_IP}:${TARGET_PORT}"
```

同时访问一个未被匹配的控制目标，确认它仍能访问，以排除 DNS、Actor 生命周期或整体网络故障。

### 8.2 恢复直连

创建 `/tmp/agentio-egress-passthrough-values.yaml`：

```yaml
egressPolicies:
- policy: PASSTHROUGH
```

恢复：

```bash
helm upgrade agentio "$AGENTIO_CHART" \
  --kubeconfig "$KUBECONFIG" \
  --namespace "$AGENTIO_NAMESPACE" \
  --reuse-values \
  --values /tmp/agentio-egress-passthrough-values.yaml \
  --wait \
  --timeout 5m
```

用新连接重试，预期重新返回 HTTP 200。

> 策略更新只会稳定影响新连接。Actor 应用如果复用 HTTP keep-alive 或连接池，旧连接可能继续沿用原结果。验证策略切换时，应新建 Actor、重启测试应用，或者让应用关闭并重新建立到目标的连接。

## 9. 将指定流量转发到 Agentio 出口网关

### 9.1 部署静态出口网关

创建 `/tmp/agentio-egress-gateway-values.yaml`：

```yaml
egressGateway:
  autoscaling:
    enabled: false
  replicas: 1
  gateways:
  - name: agentio-egress

egressPolicies:
- namespaces:
  - ate-demo-egress
  matchCidrs:
  - 10.96.35.182/32
  matchPorts:
  - "80"
  gateway:
    service: agentio-egress.agentio-system.svc.cluster.local
  policy: GATEWAY
- namespaces:
  - ate-demo-egress
  policy: PASSTHROUGH
- policy: PASSTHROUGH
```

按实际命名空间、目标地址和 gateway Service 名称修改后升级：

```bash
helm upgrade agentio "$AGENTIO_CHART" \
  --kubeconfig "$KUBECONFIG" \
  --namespace "$AGENTIO_NAMESPACE" \
  --reuse-values \
  --values /tmp/agentio-egress-gateway-values.yaml \
  --wait \
  --timeout 5m

kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  get deployment/agentio-egress service/agentio-egress -o wide
```

如果实际 Chart 生成的标签不同，直接按 `egressGateway.gateways[].name` 查找对应 Deployment 和 Service。

### 9.2 验证网关路径

使用新连接再次触发 Actor 请求，并同时查看 ztunnel 与网关日志：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  logs -l app=ztunnel --all-containers=true --prefix=true --since=5m \
  | grep -E "${TARGET_IP}:${TARGET_PORT}|gateway"

kubectl --kubeconfig "$KUBECONFIG" -n "$AGENTIO_NAMESPACE" \
  logs deployment/agentio-egress --all-pods=true \
  --all-containers=true --prefix=true --since=5m
```

至少应取得以下证据：

1. Actor 请求成功，或按网关策略得到预期拒绝。
2. ztunnel 选择了配置的 gateway，而不是直接访问目标。
3. 网关出现对应访问日志。
4. 在测试目标端查看来源地址，来源应从 Worker Pod 地址变为出口网关 Pod 地址。

仅使用 `GATEWAY` 不要求部署 EPE。需要 HTTP、域名、Header 等七层检查时，再在 gateway 上配置 EPE/ext-proc；这属于网关侧能力，不改变本文的 Ambient 捕获方式。

验证结束后，应先恢复 `PASSTHROUGH`，再删除或缩容测试 gateway，避免策略仍引用一个不存在的 Service。

## 10. 使用 TrafficPolicy 管理 Worker 流量

`TrafficPolicy` 通过 Kubernetes 标签选择 workload。当前 Substrate PoC 中，它选择的是 Worker Pod，而不是 Worker 内部单个 Actor。

下面的策略拒绝带有 `ate.dev/worker-pool=egress` 标签的 Worker 访问指定目标，并允许其他 IPv4 目标：

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: ambient-egress-target-reject
  namespace: ate-demo-egress
spec:
  priority: 100
  selector:
    matchLabels:
      ate.dev/worker-pool: egress
  egress:
    rules:
    - action: reject
      to:
      - cidr: 10.96.35.182/32
      ports:
      - port: 80
        protocol: TCP
    - action: allow
      to:
      - cidr: 0.0.0.0/0
```

将内容保存为 `/tmp/ambient-egress-target-reject.yaml`，按实际目标修改后应用：

```bash
kubectl --kubeconfig "$KUBECONFIG" apply \
  -f /tmp/ambient-egress-target-reject.yaml

kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  get trafficpolicy ambient-egress-target-reject -o yaml
```

验证：

- 目标地址应返回 HTTP 502、EOF 或连接错误。
- 未匹配的控制目标应保持可访问。
- ztunnel 日志应出现明确拒绝记录。
- 删除策略并新建连接后，目标应恢复可访问。

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  delete trafficpolicy ambient-egress-target-reject
```

不要把 Worker 上动态变化的 Actor 名称同步成 Pod label，除非明确接受频繁重建或更新 Worker 身份的控制面开销。当前单 Actor ActorContext PoC 使用的完整标签键是 `networking.agents.kruise.io/actor-name`；它只有在一 Worker 一 Actor、标签生命周期和 Actor 生命周期严格一致时，才适合作为临时 PoC 选择器，不是多 Actor 的正式身份模型。

## 11. 2026-08-24 ACK Microsandbox 实测记录

### 11.1 环境和镜像

验证集群使用 `~/.kube/my-config/substrate-network`，PoC 命名空间为 `agentio-substrate-poc`。

本次只构建并推送了发生变更或 PoC 必需的镜像：

```text
agentiod:
  docker.io/kuromesi/pilot:actor-name-3c15fe7470-20260824
  sha256:b7ef8046584671eca5e160e7371e88eb1fbca609c3fd1cc073a159cea4512cf8

ztunnel:
  docker.io/kuromesi/ztunnel:actor-workload-64c1e189db-20260824
  sha256:bfb25fa6a5a0bbdb19286a91312960dde4bef8b9b685382ba89094a29591d96a

EPE:
  docker.io/kuromesi/epe:substrate-epe-poc-v2-20260824
  sha256:29e99cc9bead13584838feebb342a20d78063853c462bc9a2ce542c3ed5334fe

带 curl 的 Actor 镜像：
  docker.io/kuromesi/substrate-egress-demo:agentio-ambient-poc-curl-systemd-flat-20260824
  sha256:9410d433d3c4d33ce9a50a645cf9a51aaac4d0f3d8551f812bc9a766394f6147
```

Actor 镜像基于 Debian bookworm，包含 `curl`、CA、systemd、SSH、iptables、nftables、socat、jq 和 Microsandbox provisioning 所需包。以下命令可以直接验证镜像中的 curl：

```bash
docker run --rm --entrypoint curl \
  docker.io/kuromesi/substrate-egress-demo@sha256:9410d433d3c4d33ce9a50a645cf9a51aaac4d0f3d8551f812bc9a766394f6147 \
  --version
```

当前 ACK 上的 ate-api 会保留 ActorTemplate CR 中的 `command`，但发给 ateom 的 `RunWorkload/RestoreWorkload` 丢失 `command` 和 `args`。因此该镜像同时注册 systemd unit，让 `/usr/local/bin/egress` 在 Microsandbox 启动时自动运行。新的 ActorTemplate 名为 `agentio-egress-curl-systemd-poc`，必须使用新名字以避免 Substrate 按模板名复用旧 DADI rootfs。

### 11.2 关闭 Substrate atunnel 出向拦截

当前安装的 Substrate 通过 ate-api 参数全局选择 atunnel egress gateway。PoC 从 `ate-api-server-deployment` 移除了：

```text
--egress-gateway-address=atenet-egress.ate-system.svc:443
```

保留了 `--atelet-insecure=true`，并完成 ate-api rollout。最终检查结果为：

```text
egressGatewayArgs: []
--atelet-insecure=true: 1 个
```

`atenet-egress` Deployment 和 Service 没有删除或关闭；该修改只让后续 Actor 的 Run/Restore 不再下发 atunnel egress gateway。回滚时把原参数加回 ate-api Deployment 并滚动 Pod。

### 11.3 首轮 PoC 资源和 Actor 身份

首轮 ActorContext PoC 使用以下主要资源；CNI 重建复测使用的对象见 11.6：

```text
namespace:      agentio-substrate-poc
Worker Pod:     agentio-ztunnel-poc-0 / 10.240.53.153
ActorTemplate:  agentio-egress-curl-systemd-poc
Atespace:       agentio-poc
Actor:          curl-actor
Actor UID:      b75ae3eb-0299-49d0-85cf-270be2a2c0d7
L4 target VIP:  172.30.49.130:80
L7 target VIP:  172.30.199.186:80
Gateway:        agentio-egress.agentio-system.svc.cluster.local
```

首轮验证时 Actor 已恢复到 `ACTOR_STATE_RUNNING`。Worker Pod 本身没有 `kruise.io/actor-name` label；节点 ztunnel 的 WDS config dump 中则存在：

```json
{
  "actorName": "curl-actor",
  "actorUid": "b75ae3eb-0299-49d0-85cf-270be2a2c0d7",
  "atespace": "agentio-poc",
  "generation": 4,
  "labels": {
    "kruise.io/actor-name": "curl-actor"
  }
}
```

这证明 Actor identity 来自 agentiod 的 ListWorkers assignment 和 `Workload.extensions["actor-context"]`，不是通过更新 Worker Pod label 模拟出来的。

### 11.4 出口网关和 EPE 配置

Agentio `agentio-config` 只把 L7 测试 VIP 路由到 Gateway，其余流量保持 PASSTHROUGH：

```yaml
egressPolicies:
- namespaces:
  - agentio-substrate-poc
  matchCidrs:
  - 172.30.199.186/32
  matchPorts:
  - "80"
  policy: GATEWAY
  gateway:
    service: agentio-egress.agentio-system.svc.cluster.local
- policy: PASSTHROUGH
```

Gateway 由 Gateway API 的 `Gateway/agentio-egress` 创建，状态为 `Accepted=True`、`Programmed=True`。EPE 仍以 `agentio-epe.agentio-system.svc.cluster.local:9002` 作为 `sandboxExtProc`，没有关闭。

当前通用 AgentioConfig 更新不会可靠地为已缓存 Ambient Workload 生成 address delta。本次通过更新 PoC Worker 的一个配置代次 label 触发该 Workload 的 WDS delta；正式版本应修复通用配置 push，而不是依赖 label 触发。

### 11.5 TrafficPolicy 和 SecurityProfile

出向四层策略使用 Worker Pod label 选择器：

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: actor-worker-egress-poc
  namespace: agentio-substrate-poc
spec:
  priority: 200
  selector:
    matchLabels:
      poc.agentio.io/profile: actor-egress
  egress:
    rules:
    - action: reject
      to:
      - cidr: 172.30.49.130/32
      ports:
      - protocol: TCP
        port: 80
    - action: allow
      to:
      - cidr: 0.0.0.0/0
```

入向策略使用相同 Worker Pod label，拒绝到 Worker ateom HTTPS 端口的新连接：

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: actor-worker-ingress-poc
  namespace: agentio-substrate-poc
spec:
  priority: 200
  selector:
    matchLabels:
      poc.agentio.io/profile: actor-egress
  ingress:
    rules:
    - action: reject
      from:
      - cidr: 0.0.0.0/0
      ports:
      - protocol: TCP
        port: 443
```

七层策略直接使用 ActorContext 的规范 label；Worker Pod 不需要这个 label：

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: curl-actor-security-poc
  namespace: agentio-substrate-poc
spec:
  priority: 100
  selector:
    matchLabels:
      kruise.io/actor-name: curl-actor
  rules:
  - name: block-curl-actor-path
    match:
    - domains:
      - 172.30.199.186
      paths:
      - type: Exact
        value: /security-denied
    actions:
      block:
        statusCode: 453
        body: blocked-by-curl-actor-security-profile
```

### 11.6 实测结果

| 验证项 | 结果 | 数据面证据 |
| --- | --- | --- |
| ActorTemplate 构建 | Ready | provisioning 报告依赖已安装；`/readyz` 第一次探测返回 200 |
| CNI 重建恢复 | 成功 | 新 Worker UID/netns 为 clean-state；CNI 日志自动生成 `physdev msb-tap+ -> 15001` 并向 ztunnel 发送新 UID |
| ztunnel 捕获 | 成功 | `physdev msb-tap+ -> 15001` counter 从 0 增长到 5 |
| TrafficPolicy 出向拒绝 | 502 | `explicitly denied by: agentio-substrate-poc/actor-worker-egress-poc-egress` |
| TrafficPolicy 出向回退 | 200 | 未匹配 VIP 正常访问 |
| TrafficPolicy 入向 selector 不匹配 | 400 | 请求到达 ateom HTTPS listener，返回原始协议错误 |
| TrafficPolicy 入向 selector 匹配 | 503 | `explicitly denied by: agentio-substrate-poc/actor-worker-ingress-poc-ingress` |
| GATEWAY 普通路径 | 200 | 后端 `RemoteAddr` 为 Gateway Pod `10.240.53.144` |
| SecurityProfile 普通路径 | 200 | EPE audit outcome 为 `passthrough` |
| SecurityProfile 拒绝路径 | 453 | CNI 重建复测的 EPE audit action 为 `curl-sandbox-cni-v1-security-poc/block-curl-actor-path` |

本次 CNI 重建复测使用以下镜像和对象：

```text
CNI image:          docker.io/kuromesi/install-cni@sha256:1bfcddb529a04586827330172bdfaf01eb3e6c0a9bffb5c3b47581eae0cecf3c
Worker Pod:         agentio-substrate-poc/agentio-ztunnel-poc-1
Worker UID:         fcc2b1f7-49eb-487e-9b62-8a29019ebdc1
Actor:              agentio-poc/curl-sandbox-cni-v1
Actor UID:          f9322676-7db0-486d-a843-7d1c1a6b540c
SecurityProfile:    curl-sandbox-cni-v1-security-poc
```

允许路径返回 200，目标服务记录的 `RemoteAddr` 为 Gateway Pod `10.240.53.144`；七层拒绝路径返回 453，EPE audit action 为 `curl-sandbox-cni-v1-security-poc/block-curl-actor-path`；四层拒绝目标 `172.30.49.130:80` 返回 502，ztunnel 记录 `explicitly denied by: agentio-substrate-poc/actor-worker-egress-poc-egress`。

可以使用已创建的普通 curl Pod检查集群内流量：

```bash
kubectl --kubeconfig ~/.kube/my-config/substrate-network \
  -n agentio-substrate-poc exec curl-client -- \
  curl -sv http://l7-security-target/security-allowed
```

Actor 侧 PoC 服务接收一个 URL 并由 Actor 发起出向请求。以下命令从 Worker 调用 Actor 服务，真正被策略判定的是 Actor 发出的第二段连接：

```bash
kubectl --kubeconfig ~/.kube/my-config/substrate-network \
  -n agentio-substrate-poc exec agentio-ztunnel-poc-1 -c ateom -- \
  wget -S -O - --timeout=20 \
  --header='Content-Type: application/json' \
  --post-data='{"url":"http://172.30.199.186:80/security-denied"}' \
  http://169.254.0.21:80/
```

预期返回 `453`。把 URL 改成 `/security-allowed` 预期返回 `200`；改成 `http://172.30.49.130:80/` 预期返回 `502`。

### 11.7 Microsandbox 当前限制

- `physdev msb-tap+` 已由 Agentio CNI 原生生成，Worker Pod 重建后可以自动恢复；不再需要 Worker init 容器或手工执行 iptables。
- Microsandbox 启动还依赖 Worker `overlaybd-forward -> NODE_IP:9862`，本文从 Worker 调用 Actor 测试端点还依赖 `169.254.0.21`。Ambient 默认 OUTPUT 捕获会影响这两类 Worker 管理流量。本次集群复测临时在 `ISTIO_OUTPUT` 前部为 TCP `9862` 和 `169.254.0.21/32` 添加 `ACCEPT`；这两条 bypass 仍是运行时 PoC 配置，Pod 重建后会丢失。正式方案应把它们表达成受校验的 CNI Pod 级排除配置，或者调整 Substrate 管理链路，使其使用 ztunnel 可安全识别的 mark/独立 netns。
- 不能用 `br-msb -> 15001` 替代 `physdev`。实测会把 atenet-router 到 Worker 的入向连接误分类为出向，从而绕开入向 TrafficPolicy 的正确方向判定。
- 当前社区 ate-api 部署版本丢失 ActorTemplate 的 `command/args`，PoC 镜像用 systemd unit 规避；应升级或修复 ate-api 后取消这个兼容措施。
- 本次删除旧 Worker 时，原 Actor 先变为 `CRASHED`；一次在缺少 `9862` bypass 时失败的冷启动又让社区控制面把新 Actor 卡在 `RESUMING`。当前部署版本没有 `DeleteActor.any_state`，PoC 因而创建第二个 Worker 和新 Actor 完成复测。该问题属于社区 Substrate 的失败恢复/状态机边界，不是 CNI `physdev` 规则失败。
- 当前一个 Worker 同时只绑定一个 Actor。多 Actor 共用 `br-msb` 时，只有接口级捕获无法区分 Actor，需要按 TAP、IP、mark、cgroup/socket cookie 或独立 netns 建立 per-flow Actor identity。

### 11.8 在实际 Sandbox 中执行 curl

`ateom` 不是 Actor Sandbox。它运行在 Worker Pod 中，是 Substrate 的 Actor herder 和 Sandbox 驱动：负责创建、恢复、暂停、快照 Microsandbox，维护 TAP/bridge 网络，并在 Worker 和 Sandbox 之间执行 readiness、checkpoint 等管理操作。对 `ateom` 使用 `kubectl exec`，进入的是 Worker Pod netns，不是 Actor 的 PID、mount 或 network namespace。

当前社区 `kubectl ate` 提供 Actor 生命周期、查询和日志接口，但没有通用的 `exec actor` API。为了验证 curl 确实在 Microsandbox 内执行，本 PoC 使用受限 HTTP 端点：Worker 只把一个经过校验的 `http/https` URL 传给 Actor；Actor 内的服务固定执行 `/usr/bin/curl`，不接受任意 shell 命令。

最终镜像和资源如下：

```text
Image tag:     docker.io/kuromesi/substrate-egress-demo:agentio-ambient-poc-sandbox-curl-flat-v3-20260824
Image digest:  sha256:58ca036213243a8faa20b27cc0c4685ba190a580bdb18b27f30221f03691330f
ActorTemplate: agentio-sandbox-curl-flat-v3-poc
Actor:         agentio-poc/curl-sandbox-cni-v1
Actor UID:     f9322676-7db0-486d-a843-7d1c1a6b540c
Worker Pod:    agentio-substrate-poc/agentio-ztunnel-poc-1
```

镜像必须扁平化为单个 OCI layer。当前 Microsandbox/DADI 解压普通多层镜像时可能报 `untar layer 1: operation not supported`。同时镜像必须预装 `git`、`nfs-common` 和 `less`；否则 provision 阶段会尝试访问 Debian 软件源，而 Sandbox 构建网络不一定可达该软件源。

测试链路为：

```text
Worker ateom 中的 wget/nc
  -> 169.254.0.21:80（Actor 内受限测试端点）
  -> Actor Sandbox 内 exec /usr/bin/curl
  -> msb-tap+ -> Worker 15001 -> ztunnel
  -> Agentio Gateway -> EPE -> 目标服务
```

下面的 `nc` 只负责调用 Actor 端点。目标 TCP 连接由响应中 `execution.binary=/usr/bin/curl` 对应的 Sandbox 进程发起：

```bash
kubectl --kubeconfig ~/.kube/my-config/substrate-network \
  -n agentio-substrate-poc exec agentio-ztunnel-poc-1 -c ateom -- \
  sh -c 'body='"'"'{"url":"http://172.30.199.186:80/security-allowed"}'"'"'; \
    length=${#body}; \
    printf "POST / HTTP/1.1\r\nHost: 169.254.0.21\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" \
      "$length" "$body" | nc -w 25 169.254.0.21 80'
```

2026-08-24 实测响应中的 Sandbox 证据：

```json
{
  "binary": "/usr/bin/curl",
  "curlVersion": "curl 7.88.1 (x86_64-pc-linux-gnu) ...",
  "pid": 180,
  "hostname": "aliyun.local",
  "pidNamespace": "pid:[4026531836]",
  "networkNamespace": "net:[4026531994]",
  "mountNamespace": "mnt:[4026531840]",
  "cgroup": "0::/system.slice/agentio-egress-poc.service"
}
```

目标服务还观察到 `User-Agent: curl/7.88.1`，并且允许请求的 `RemoteAddr` 为 Agentio Gateway Pod IP `10.240.53.144`。三类实际 Sandbox curl 请求结果如下：

| 场景 | Sandbox curl 结果 | 策略证据 |
|---|---:|---|
| `security-allowed` | 200 | 经 Gateway 到达目标，EPE `passthrough` |
| `security-denied` | 453 | 返回 `blocked-by-sandbox-curl-security-profile`，按 `kruise.io/actor-name=curl-sandbox-cni-v1` 命中 SecurityProfile |
| `172.30.49.130:80` | 502 | curl `Recv failure: Connection reset by peer`，ztunnel 命中 `actor-worker-egress-poc-egress` |

测试服务源码、测试和镜像定义位于：

```text
tests/integration/agentio/testdata/substrate-curl-sandbox/
```

## 12. 关键故障排查

### 12.1 Worker 没有 `ambient.istio.io/redirection=enabled`

依次检查：

- `ambient.enabled=true`，CNI 与 ztunnel DaemonSet Ready。
- Worker Pod 标签确实为 `istio.io/dataplane-mode=ambient`。
- 修改标签后是否重建了 Worker Pod。
- CNI 的 `enablementSelector` 是否允许该标签或所在命名空间。
- CNI 日志是否报告 netns、ZDS 或 iptables 编程失败。

### 12.2 `15001` 端口冲突

如果 Worker netns 中 atunnel/ateom 仍监听 `15001`，ztunnel 无法建立 Ambient 出口 socket。把 atunnel egress 监听地址改到其他本地端口，例如 `127.0.0.1:15099`，然后重建 Worker。

### 12.3 ztunnel 有监听，但 Actor 流量没有命中

检查：

- gVisor Worker 是否存在 `istio.io/reroute-virtual-interfaces: ateom0`，且真实网卡名称仍为 `ateom0`。
- Microsandbox 是否实际使用 `br-msb/msb-tap*`，以及 `ISTIO_PRERT` 是否使用 `physdev --physdev-in msb-tap+ -> 15001`。
- 不要看到 `br-msb` 后就直接配置 `-i br-msb -> 15001`；先确认它是否同时承载 Worker Pod IP 和正常入向流量。
- 查看规则 packet counter，请求前后是否增长。
- 使用的检查命令是否匹配节点实际的 nft/legacy 后端。

### 12.4 配置 DENY 后 Actor 无法启动

不要直接配置无条件的全局 `DENY`。Worker 到 Actor 的 readyz、checkpoint 或其他内部 TCP 流量也可能经过 `ateom0` 和 ztunnel，例如 `169.254.17.2:80`。应先按命名空间、目标 CIDR 和端口缩小范围，并保留 `PASSTHROUGH` 兜底。

### 12.5 策略已经更新，但请求结果没变

最常见原因是 Actor 复用了既有 TCP/HTTP keep-alive 连接。检查 ztunnel 是否收到了配置更新，然后用新 Actor 或新连接验证。不要仅凭一个已存在的长连接判断策略未生效。

### 12.6 Actor 卡在 `RESUMING`

检查 Worker 到 Actor 的 readyz、checkpoint 和 atenet-router 链路。PoC 中曾出现 Actor 生命周期竞态，此时 ztunnel 没有拒绝日志；换用新的 Worker/Actor 后恢复。该现象和 Ambient 捕获失败要分开判断。

### 12.7 atenet-router 请求在到达 Actor 前失败

检查 router Pod、Service、证书和日志。router 证书过期会在 Actor 执行前就导致 TLS 失败，不能用来判断 Actor 出口策略。

### 12.8 手工修改被恢复

这通常是 Worker controller 的 reconcile 行为。PoC 可以暂时隔离 controller，正式环境必须把 Ambient 标签、注解和 atunnel 端口写入 Worker 模板的 source of truth。

## 13. 清理与恢复

建议按以下顺序恢复：

1. 把 `egressPolicies` 恢复成全局 `PASSTHROUGH`。
2. 删除测试 `TrafficPolicy`。
3. 删除测试 Actor，等待 Actor 资源和运行实例清理完成。
4. 恢复 Worker 模板、atunnel 端口和管理 controller。
5. 确认没有 Worker 仍依赖 Ambient 后，再关闭 `ambient.enabled`。
6. 删除测试出口网关或恢复原网关副本数。

恢复出口策略：

```bash
helm upgrade agentio "$AGENTIO_CHART" \
  --kubeconfig "$KUBECONFIG" \
  --namespace "$AGENTIO_NAMESPACE" \
  --reuse-values \
  --values /tmp/agentio-egress-passthrough-values.yaml \
  --wait \
  --timeout 5m
```

删除测试策略：

```bash
kubectl --kubeconfig "$KUBECONFIG" -n "$WORKER_NAMESPACE" \
  delete trafficpolicy ambient-egress-target-reject --ignore-not-found
```

如果需要完全关闭 Ambient，创建一个明确的恢复 values 文件并通过 Helm 升级，不要直接删除 DaemonSet：

```yaml
ambient:
  enabled: false
```

恢复后检查 Worker 是否回到预期的数据面模式，并重新验证 Actor 的启动、入向访问和出向访问。

## 14. 正式化建议

PoC 验证完成后，正式接入建议补齐以下能力：

- 在 WorkerPool/controller 层原生支持 Pod 标签、注解和 atunnel egress 端口，避免直接 Patch Deployment。
- 将 `agentio.io/reroute-bridge-port-prefixes` 从 PoC 能力正式化，补齐版本化文档、升级兼容和端到端回归；同时增加受校验的 Pod 级 OUTPUT 排除配置，至少覆盖 Microsandbox `overlaybd-forward :9862` 和必要的 Worker 管理地址。
- 对 CNI 纳管、ZDS 连接、Worker netns socket、策略下发和 gateway 转发增加监控及告警。
- 为每次策略变更提供新的 TCP 连接验证，避免 keep-alive 造成假阴性。
- 默认生成最小范围的目标规则，并保留显式兜底，禁止直接下发无范围的全局 `DENY`。
- 明确 Worker 级和 Actor 级身份边界。多 Actor 正式方案需要 agentiod 获得 Actor 生命周期与 Worker 归属，并让数据面建立“Actor 地址/连接 -> ActorContext”的可靠绑定；仅把 Actor 名称写入共享 Worker label 无法表达并发多 Actor。
- 如果启用出口网关和 EPE，应分别验证四层路由、网关 mTLS、七层 ext-proc 策略、上游 TLS 与自签 CA 信任。

## 15. 相关文档

- [Agentio Ambient 模式入门](../getting-started/ambient-mode.md)
- [通过出口网关路由流量](./route-traffic-through-egress-gateway.md)
- [配置 TrafficPolicy](./configure-traffic-policy.md)
- [Agentio 配置参考](../reference/agentio-configuration.md)
