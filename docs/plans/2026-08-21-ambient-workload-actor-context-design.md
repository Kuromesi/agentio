# Ambient Workload ActorContext 扩展设计

## 目标

让 sidecar 和 Ambient ztunnel 都从源 Worker 的 Workload API 资源获得 ActorContext。Substrate `ListWorkers` 继续作为权威绑定来源，Worker Pod mTLS 身份继续作为传输身份。

## 数据模型

复用 `istio.workload.Workload.extensions`，为已分配 Actor 的 Worker 添加：

```text
name: actor-context
type_url: type.googleapis.com/kruise.networking.extensions.v1.ActorContext
value: ActorContext protobuf
```

ActorContext 只包含 Actor UID、name、atespace、generation 和策略 labels，不包含 token。agentiod 在追加扩展前必须以 namespace、Pod name 和 Kubernetes Pod UID 精确匹配 ListWorkers assignment。

## 控制面行为

agentiod 保留基础 Workload 对象不变，在为 ztunnel 生成 Address xDS 响应时克隆并追加 ActorContext：

- dedicated sidecar ztunnel 只获得自身 Worker 的 ActorContext；
- node-level ztunnel 只获得与自身 `NODE_NAME` 相同的 Worker ActorContext；
- 普通 proxy 和其他节点的 Workload 不获得 ActorContext；
- ListWorkers 启用且 Worker 未分配时不回退到 Pod Actor labels；未启用时保留 labels 兼容路径。

ListWorkers 快照变化时，除保留强制 WCDS push 以兼容旧 sidecar 外，还要把发生变化的 Worker Workload UID 放入 `PushRequest.AddressesUpdated`，触发 Address delta。初次连接的 wildcard Address 响应也应用同样的动态装饰逻辑。

## ztunnel 行为

ztunnel 解码 ActorContext typed extension，并把它保存在对应的内部 `Workload` 上。创建 HBONE CONNECT 时优先读取 `req.source.actor_context`，旧版 WCDS 单值 ActorContext 仅作为迁移兼容路径。

Workload Store 更新时，连接观察器比较每条连接开始时的源 Workload Actor `(uid, generation)` 和当前同 Workload UID 的 Actor。只关闭发生变化的 Worker 连接，不关闭 node ztunnel 上其他 Workload 的连接。WCDS 单值变化仍保留原有全局 drain，以兼容只使用旧协议的 dedicated sidecar。

## 安全与兼容性

- 不向 Workload API 下发 Actor token。
- Actor assignment 删除后发送不含 ActorContext 的同一 Workload delta，ztunnel 必须清除旧身份并 drain 对应连接。
- 未识别 typed extension 的旧 ztunnel 会忽略它，因此 wire 兼容；Actor 策略侧必须 fail closed，避免旧数据面静默降级。
- 任何 workload 更新失败都不能回退到 workload 可修改的 Actor labels。
- 现有 WCDS ActorContext 暂时保留，后续在所有 sidecar 升级后单独移除。

## 验证范围

- Go：扩展编码、按节点/自身装饰、Pod UID 防重用、不修改共享 Workload、绑定变化 Address push。
- Rust：typed extension 解码、源 Workload Actor headers、未分配时无 Actor headers、per-Workload drain。
- KinD：无 Actor Pod labels 的 Ambient Worker获得扩展；PASSTHROUGH/GATEWAY 请求携带正确 Actor 元数据；暂停 Actor 后扩展清除并只 drain 目标 Worker。
