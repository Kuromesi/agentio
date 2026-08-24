# Substrate PREROUTING-only CNI 设计

## 目标

为 Substrate Worker Pod 提供显式的 `agentio.io/interception-mode: prerouting-only` 模式。该模式只把通过显式 Actor 选择条件进入 Pod 网络命名空间的 TCP 流量重定向到 ztunnel，不捕获 Worker Pod 中 `microsandbox-daemon`、`ateom`、`overlaybd-forward` 或 ztunnel 自身创建的本地 `OUTPUT` 连接。

## 适用边界

- Actor 运行在独立网络栈中，数据流通过 TAP、bridge 或其他虚拟接口进入 Worker Pod 网络命名空间。
- Actor 出向 TCP 通过 `PREROUTING` 捕获。
- Worker 本地进程不作为 Actor 工作负载，不继承 ActorContext。
- 默认模式保持现有 Sidecar 和 Ambient 行为，保证未配置该注解的 Pod 不受影响。

## 配置接口

```yaml
metadata:
  annotations:
    agentio.io/interception-mode: prerouting-only
    agentio.io/reroute-source-ip-ranges: 169.254.0.21/32
```

Sidecar CNI 继续支持标准虚拟接口选择：

```yaml
metadata:
  annotations:
    agentio.io/interception-mode: prerouting-only
    istio.io/reroute-virtual-interfaces: ateom0
```

当前 Microsandbox bridge+TAP 模型优先使用 Actor 源 CIDR；`ateom0` 只适用于内核在 `PREROUTING` 中确实能看到该接口的运行时。

## 规则语义

### Ambient CNI

开启该模式后仅生成显式 Actor reroute 规则：

```iptables
-A PREROUTING -j ISTIO_PRERT
-A ISTIO_PRERT -s 169.254.0.21/32 -p tcp ! --dport 15001 \
  -j REDIRECT --to-ports 15001
-A ISTIO_PRERT -s 169.254.0.21/32 -p tcp -j RETURN
```

不生成以下规则：

- `nat OUTPUT -> ISTIO_OUTPUT`；
- `mangle OUTPUT -> ISTIO_OUTPUT`；
- Worker 本地 DNS OUTPUT 捕获；
- 普通 Pod 入向 TCP 的 `PREROUTING -> 15006` catch-all。

`reroute-source-ip-ranges`、`reroute-bridge-port-prefixes` 和 `reroute-virtual-interfaces` 仍可作为显式 Actor 选择条件。

### Sidecar CNI

Sidecar CNI 读取相同的 interception mode，并把它传入 iptables/nftables 规则生成器。开启后保留 `reroute-virtual-interfaces` 对应的 `PREROUTING` redirect，但不创建 NAT/RAW/MANGLE 的本地 OUTPUT 捕获路径。普通入向配置保持由现有 `includeInboundPorts` 控制。

Sidecar CNI 当前不解析 `agentio.io/reroute-source-ip-ranges`；该选择器由 Ambient in-pod 规则路径实现。后续若 Microsandbox 必须使用 ztunnel sidecar 且 `ateom0` 无法命中，再单独把 source-CIDR 规则复用到 Sidecar 生成器，避免本次改动扩大到上游 sidecar API。

## 校验与失败处理

- 注解缺失时使用默认全量行为。
- 值等于 `prerouting-only` 时启用新模式。
- Ambient 遇到未知值时记录告警并回退默认行为。
- Sidecar CNI 遇到未知值时拒绝生成 Redirect 配置，避免错误配置静默放宽或改变流量边界。

## 测试

- Node agent 测试覆盖有效、空白和非法注解值。
- Ambient iptables 和 nftables 测试同时断言 Actor PREROUTING redirect 存在、OUTPUT redirect 与普通入向 catch-all 不存在。
- Sidecar Redirect 解析测试断言新模式能传递到规则配置。
- Sidecar iptables 和 nftables 规则测试断言虚拟接口 PREROUTING redirect 存在、OUTPUT hook 不存在。
- 默认 golden tests 证明未配置注解时规则没有变化。
