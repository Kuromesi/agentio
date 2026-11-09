# SecurityProfile TCP gateway review

2026-11-06，`ssh my-ecs`，独立 Kind 集群 `sp-tcp-review`。

本次验证：**32/32 固定流量用例、9/9 策略变化用例通过**。所有业务 Pod Ready，未重启。集群、测试服务、镜像、源代码、配置和日志均保留，不执行自动清理。没有修改另外两个 Kind 集群。

## 进入现场

```bash
ssh my-ecs
cd /root/agentio-sp-tcp-review-20261106
export KUBECONFIG="$PWD/kubeconfig"
kubectl get pods -A
kubectl -n review-clients get securityprofiles,trafficpolicies,sandboxes
```

| 对象 | 用途 |
| --- | --- |
| `agentio-system` | 本次编译的 Agentiod、EPE、Porter、原生 Envoy 网关 |
| `review-clients/empty` | 无 SP，验证默认放行 |
| `review-clients/locked` | TCP 全拒绝，指定 HTTP bypass、TLS passthrough 作为例外 |
| `review-clients/guarded` | Header 注入后按实际地址检查 TCP 规则；指定端口优先允许 |
| `review-clients/inline` | Sandbox 内联 HTTP/TCP 规则；共享 SP 优先允许 TCP 9000 |
| `review-clients/hot` | 热更新、非法更新保留上一份有效配置，最终为 allow |
| `review-clients/tp` | SP bypass，但 TrafficPolicy 在 ztunnel 拒绝原始目标 |
| `review-upstream/upstream` | HTTP/TLS/TCP 测试服务及对应 DNS Service |
| Docker `sp-review-upstream` | 集群外测试目标，位于 Kind 网络；避免 raw TCP 被当成 mesh 内流量直连 |

## 复测和查看日志

```bash
# 只发流量，不修改配置；约十几秒。
python3 run.py

# 重放策略变化，会修改本测试集群中 hot、inline、tp 的测试策略。
# 最后恢复到本次保存的策略状态。
python3 transitions.py

# 重新保存日志、Envoy 配置和 Kubernetes 对象。
bash collect.sh

cat results/latest.json
cat results/transitions-latest.json
kubectl -n agentio-system logs deploy/egress-gateway -c agentio-proxy -f
```

`run.py` 依赖已保留的测试对象和策略。`setup-inline.py` 是内联 Sandbox 的构建记录；当前对象已存在，无需重复执行。

手动查看两个对照：

```bash
# TCP deny-all 下，指定 HTTP 域名依然 bypass，返回 200。
kubectl -n review-clients exec locked -c client -- \
  python /review/probe.py http allowed.review-upstream.svc.cluster.local 198.51.100.1 8080

# 原始地址 198.51.100.1 不在私网 deny 中，但 Host 解析为私网地址，返回 403。
kubectl -n review-clients exec guarded -c client -- \
  python /review/probe.py http mutate.review-upstream.svc.cluster.local 198.51.100.1 8080

# 同一 Header 注入规则，18080 端口先命中 allow，返回 200 并回显 x-review-token。
kubectl -n review-clients exec guarded -c client -- \
  python /review/probe.py http mutate.review-upstream.svc.cluster.local 198.51.100.1 18080
```

## 覆盖范围和证据

- Raw TCP、server-first 嗅探超时：默认放行与 deny 均验证。
- HTTP：bypass、block、没有规则命中、Header 注入后 fallthrough；按解析后的 IP 检查，允许后到达预期 Service 地址。
- TLS：SNI 未匹配及无 SNI 使用原始地址；显式 Deny；显式 Passthrough 通过 SNI DNS 转发到原始地址之外的目标，保留上游证书；非默认 TLS 端口 8443。
- TLS 终止后：HTTP bypass/block/IP deny；非 HTTP 流量依据 TCP 决策允许或拒绝，允许时连接原始目标并重新建立 TLS。
- Sandbox：单 Sandbox/Pod 的内联规则、HTTP bypass、共享 SP 规则优先级。
- 热更新：allow → deny → 非法 CIDR（保留上一份 deny）→ allow。非法状态另存于 `results/invalid-policy-status.json`。
- TrafficPolicy：安装前 HTTP 成功，安装后由 ztunnel 拒绝；日志明确记录 `namespaces/review-clients/trafficPolicies/tp/rule-0`，见 `logs/ztunnel-tp.log`。

`results/final-state/` 保存最终 Pod、策略、网关 listener/cluster 配置、stats 和镜像 ID；`logs/` 保存组件日志和每轮测试输出。

## 构建和环境

- 基线：agentio `upstream/master`，`bc627aa574ae8b992733f96597472c799307084d`，叠加 `codex/sp-tcp-gateway-policy` 未提交的改动。
- 源代码：`agentio/`；本地 API 配套源码：`agents-api-sp-tcp-gateway-policy/`，通过 `go.work` 使用。
- `build.sh` 编译 Go 与 Rust；`images.sh` 记录镜像组装。四个改动组件全部重新编译，gateway 保留已有 Envoy 1.40.2 和未改动的其他动态模块。
- ztunnel 使用已有 `kuromesi/agentio-scale:reconnect-20261106-ztunnel`，本次未修改其代码。
- 镜像：`sp-review/{agentiod,epe,porter,gateway}:20261106`。镜像 ID 见 `results/final-state/images.txt`。
- 新 SP/GlobalSP CRD 从配套 agents-api 源码单独安装；未发布新 API 依赖，不能仅使用旧 chart CRD 复现。
- 远端 Kind 镜像加载命令存在 snapshotter 兼容问题，最终用 `docker save | docker exec ... ctr --namespace k8s.io images import --snapshotter overlayfs -` 成功导入。
- 最初测试 TLS action 多写了 `schemes`，被现有验证器拒绝，修正为只含域名后重新运行通过。旧日志保留此预期配置错误。
- 测试 TLS 证书有效至 2026-11-20；客户端为观察网关终止行为不校验下游证书，终止后网关仍校验测试上游证书。

未覆盖 IPv6、UDP、并发压测、多节点和同一宿主多个 Sandbox 的运行时身份绑定路径。Sandbox 测试覆盖单 Sandbox 的 Workload 兼容投影，不声称验证了多租户共享宿主链路。


## Filter state 与 dynamic metadata 对照

在 my-ecs 上单独运行 Envoy 1.40.2，使用 CONNECT HCM → internal listener → TCP upstream 的链路。实验没有修改已保留的 Kind 集群。

| 传递方式 | 结果 |
| --- | --- |
| 只有 CONNECT dynamic metadata | 内部 listener 的 dynamic metadata 和决策 filter state 都为空，全部拒绝 |
| 共享 `envoy.string` | 保持第一条 allow 隧道打开后，后续两条 deny 都被错误放行；内部日志显示读取到旧 allow |
| 共享 `envoy.hashable_string` | allow 放行、deny 拒绝；交替请求 204 次均符合预期 |

普通 string 的问题需要保留活动连接才能复现：首次使用一次响应后立即关闭的测试上游时没有复现；改为保持连接、持续回显的上游后复现。即使没有重复使用同一条 TCP 连接，连接池保留的 transport socket options 仍会影响新连接。

Envoy 1.40.2 的 internal_upstream.passthrough_metadata 只支持 Host/Cluster metadata，不支持每个请求的 dynamic metadata；不能直接用它复制 Porter 的请求决策。

内部传递保留 hashable filter state。通过 static cluster metadata 也可以传递固定决策，但需要拆分内部 cluster 和后续路由，不会自然消除分池。后续已验证并实现停止传播，见下文。

脚本：`/root/agentio-sp-tcp-review-20261106/state-experiment.py`；配置、stats、内部连接日志和结果：同目录 `state-experiment/`。实验容器已停止并保留，原业务集群仍运行。

尝试配置 `max_connection_pools` 并观察 `remaining_cx_pools`，但这些计数在本实验的 TCP 路径中没有反映实际池的分配，不能用于证明池数量上限。本次没有量化真实业务规模下的池数量或内存增量。


## 最后消费点停止共享

已在最终转发 chain 的 terminal filter 之前增加 `agentio.local_tcp_decision`：读取已有决策，使用普通 `envoy.string` 重设同名状态，并设置 `shared_with_upstream: NONE`。本地值保留，后续创建上游连接时不再携带这个对象，也不再因它分池。

- MainInternal 的 HTTP、原始 TCP、显式 TLS passthrough chain 停止共享。
- TLS termination chain 继续传递到 MainForward。
- MainForward 的 HTTP、非 HTTP chain 停止共享。
- 拒绝 chain 不建立实际业务上游连接；legacy gateway 保持原有配置。

`state-localize.py` 的两跳隔离实验确认：原有 TRANSITIVE 会让后一跳继续读到 allow；重设为 NONE 后，本地仍读到 allow，后一跳记录为 null，allow/deny 判定不变。Envoy 1.40.2 的 `read_only` 字段已弃用、没有效果，此处重设不依赖修改只读对象的能力，也没有调用不存在的 unset API。

`go test ./pkg/networking` 通过。远端更新 Agentiod 镜像为 `sp-review/agentiod:20261106-local-decision`；从实际 Envoy admin 回读确认五个终端转发 chain 已包含新 filter。32 个流量用例和 9 个策略变化用例全部通过。控制面 rollout 期间首轮有两个 TLS 握手失败；配置收敛后完整重跑 32/32 通过，这次优化不声称解决控制面切换期间的 TLS 可用性问题。

原 Agentiod 镜像保留，替换前 Deployment 和日志在 `results/before-local-decision/`；当前集群保留优化后的配置。部署过程见 `local-decision.sh`，流量和变化记录分别在 `logs/matrix-local-decision-final.log` 和 `logs/transitions-local-decision.log`。未量化全量业务的内存和连接池节省。


## 连接池与内存量化

在 my-ecs 上使用同一 Envoy 1.40.2 镜像做隔离对照，未修改保留的业务集群。链路为 CONNECT HCM → internal listener 的 HTTP chain → DFP HTTP/1.1 上游。Porter/EPE 用可控的测试决策和直接进入 HTTP 转发链路代替，表示两种原始 TCP 决策都被 HTTP bypass 允许的情况；本实验测这个共享字段的增量，不是产品全链路吞吐测试。

固定一个 worker、同一身份、两个持续打开的 CONNECT 隧道。后端是 1/32/128/512 个不同端口的 HTTP 保活地址；只有终端 chain 是否将 decision 重设为 NONE 不同。每组新建 Envoy 进程，交错顺序重复三轮，表中是三轮中位数。每次进程共成功处理 10,516 个 HTTP 请求，池溢出为 0。内存通过 Envoy `/memory` 的 allocated 读取，RSS 通过 Envoy 进程 `/proc/PID/status` 读取；新增堆内存表示减去各自两条隧道已建立、尚无后端连接时的基线。

### allow 与 deny 混合，HTTP 均允许

| 上游地址数 | HTTP 池/空闲连接：优化前 → 后 | 新增堆内存：前 → 后 | 节省 |
| --- | --- | --- | --- |
| 1 | 2 → 1 | 69.6 → 52.0 KiB | 17.7 KiB |
| 32 | 64 → 32 | 1.19 → 0.65 MiB | 0.54 MiB |
| 128 | 256 → 128 | 4.69 → 2.50 MiB | 2.19 MiB |
| 512 | 1024 → 512 | 18.63 → 9.86 MiB | 8.77 MiB |

512 地址时，新增堆内存减少约 47%；实际进程总 allocated 中位数为 25.01 → 16.24 MiB（约 35%），不能把 47% 当作总进程内存的下降比例。新增 RSS 为 20.09 → 11.00 MiB。三轮新增堆内存范围分别为 18.61–18.67 MiB 与 9.85–9.92 MiB。

HTTP 池数通过可正常计数的 `http_out` HTTP cluster 的 `8192 - remaining_cx_pools` 得到，并与 `upstream_cx_active` 交叉核对；两项均精确符合表格。这里没有使用先前不能反映 TCP 池分配的统计。

### 两个隧道始终都是 allow

此时没有因 decision 值不同造成的拆池。512 地址时，池数和空闲连接均为 **512 → 512**；新增堆内存 **10.01 → 9.87 MiB**，仅节省 **0.14 MiB（约 1.4%）**。因此不能承诺所有业务都减少一半连接池：主要收益出现在同一个已有池 key 下出现 allow/deny 两种值的场景。

两种场景、两个版本的预热后测量请求都没有新建上游连接，稳态复用率均为 100%。请求延迟存在宿主机噪声和 Python 驱动开销，未据此声称 QPS 或延迟改善。测量的是单 worker、HTTP/1.1 稀疏请求的保活资源占用，没有测 TLS/H2、并发饱和负载或完整产品链路。

复测脚本 `/root/agentio-sp-tcp-review-20261106/pool-benchmark.py`：

```bash
cd /root/agentio-sp-tcp-review-20261106
python3 pool-benchmark.py
BENCH_DECISIONS=allow,allow python3 pool-benchmark.py
```

两条命令顺序执行，脚本占用独立测试端口。脚本把本进程和测试容器的 nofile 设为 65536，以支持 512 个地址和最多 1024 条后端保活连接；没有修改主机或原集群的全局限制。结果、每轮配置和容器日志分别在 `pool-benchmark/`、`pool-benchmark-uniform/`，包含 `results.json`、`summary.json` 和各轮 `*-stages.json`。测试容器已停止并保留，Kind 业务集群仍保留优化后的配置。


## Porter Rust 本地基准

在本机 Apple M4、16 GiB、macOS 27.0.1、Rust 1.97.1 上以 release/thin-LTO 运行。基线是 `bc627aa574ae8b992733f96597472c799307084d` 的原 TrafficPolicy bench；当前版本复用该 bench，将输入迁移为内联 TCPPolicy，并校验返回的 `allow` 决策。两者的规则匹配、20 个标签、8 条 SNI 规则、证书属性和目标地址相同，资源编码和发现拓扑分别遵循各自 API；不是字节相同的线协议输入。

冷路径每组 100 个新 Workload；热路径先预热 1000 次，然后分别测 8000 次 handler、8000 次并发 1 gRPC、8000 次并发 16 gRPC。三轮交错基线/当前顺序，所有 6 轮均通过，共 120 条结果、723,000 次计时请求。下表是各轮中位数。

| 逻辑策略×规则数 | 冷 handler+TLS ADS P50 μs：旧 → 新 | 热 handler P50 μs：旧 → 新 | gRPC C16 RPS：旧 → 新 |
| --- | --- | --- | --- |
| 0x0 | 49.04 → 50.54 | 5.67 → 5.42 | 52,860 → 51,296 |
| 1x16 | 103.00 → 52.62 | 5.62 → 5.25 | 52,667 → 52,106 |
| 8x16 | 130.29 → 76.96 | 6.25 → 5.46 | 52,381 → 52,492 |
| 8x128 | 253.04 → 260.75 | 7.12 → 7.33 | 47,507 → 50,468 |
| 32x32 | 279.96 → 249.25 | 9.12 → 7.71 | 47,709 → 52,100 |

16/128 条规则的冷加载明显减少，1024 条规则的结果取决于旧策略的组织方式：8×128 的冷 P50 略增，32×32 降低。因此不将本次结果概括成全面提速。当前并发 1 gRPC 约 1.21–1.28 万 RPS，并发 16 约 5.05–5.25 万 RPS。循环 wall time 包含响应校验，当前 bench 还校验 TCP decision；不是单独 CIDR 匹配函数的耗时。

当前规则全部是 IPv4 CIDR/端口，最末规则允许目标，测的是完整扫描路径。空规则默认放行。`8x128` 与 `32x32` 在当前模型中均是 1024 条内联规则，名称保留逻辑分组，用于和原 TrafficPolicy 引用模型比较。

复测：

```bash
PORTER_BENCH_REQUESTS=8000 cargo test --release --locked \
  --manifest-path extensions/porter/Cargo.toml --test tcp_benchmark \
  -- --ignored --nocapture --test-threads=1
```

原始日志、每轮数据和汇总在本地验证 artifacts 的 `porter-local-bench/`，包括 `environment.json`、`results.json`、`summary.json`、六份运行日志和构建日志。对应测试已保留在 `extensions/porter/tests/tcp_benchmark.rs`，README 已更新执行入口。

这里使用 macOS 系统分配器，没有测 Linux jemalloc、Sandbox 绑定分支、IPv6、缓存容量压力或 5 万以上资源的规模测试；不能据此推断集群或完整网关吞吐。


## 完整 SecurityProfile JSON 接收成本（2026-11-07）

本次只增加 bench，没有接入完整 JSON 的生产 xDS 路径，没有改动已保留集群。测试环境为本机 Apple M4、16 GiB、Rust 1.97.1、macOS 系统分配器、release 构建。

样本由 `extensions/porter/tests/sp_json_fixtures.go` 生成：使用实际 agents-api Go 类型构造 SP，再调用当前 Go `CompileSecurityProfile` 生成基准 protobuf。HTTP 规则覆盖 http-only、HTTPS、路径和方法限制，域名大小写、尾点、重复泛域名，以及显式 TLS passthrough/deny；Header 修改包含 2–16 个字段、每个值 64–1024 字节。TCP 采用首条命中语义，计时目标的放行规则位于最后，分别覆盖 0、16、128、1024 条规则。

`sp_json_benchmark.rs` 比较三条接收路径：

- `protobuf`：解码已投影的 SNI/TCP protobuf，调用现有 Rust TCP 编译器。
- `json_selective`：直接反序列化到 Porter 所需的部分类型，跳过 HTTP actions 等字段；在 Rust 中完成 SNI 投影，再调用同一个 TCP 编译器。
- `json_value`：先建立完整 `serde_json::Value` 树，再转换为部分类型并完成同样的投影；不保留该树。

每种 JSON 路径都核对 SNI 与真实 Go 编译结果完全相同，并对五个目标地址/端口核对 TCP 判定和 SNI 元数据；另检查非法 CIDR 被拒绝。所有断言通过。每阶段预热 32 次、计时至少 100 ms，五轮交替执行顺序；下表是五轮「每次平均耗时」的中位数，包含创建及释放编译对象，不是单次延迟 P50/P99。

| 样本 | JSON 字节 | SNI+TCP protobuf 字节 | SNI/TCP 规则数 | protobuf 接收 µs | 选择性 JSON µs | 完整 Value 后转换 µs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| empty | 171 | 2 | 0/0 | 0.014 | 0.168 | 0.431 |
| small | 5,232 | 876 | 8/16 | 3.293 | 8.548 | 18.395 |
| typical | 67,879 | 6,852 | 50/128 | 23.828 | 69.988 | 154.501 |
| tcp-heavy | 96,489 | 38,705 | 8/1024 | 160.437 | 236.860 | 466.637 |
| many-http | 367,409 | 13,449 | 194/128 | 37.460 | 192.611 | 464.263 |
| http-heavy | 1,098,627 | 2,765 | 50/16 | 7.148 | 140.909 | 308.776 |
| http-heavy-escaped | 1,622,923 | 2,765 | 50/16 | 7.039 | 2614.940 | 3450.526 |

热路径计时使用 `192.0.2.1:443`，非空 TCP 链命中末条放行规则；TCP 匹配和逐连接 SNI 元数据生成使用相同缓存结构，三条输入路径的热路径结果没有明确的性能退化：例如 typical 的 protobuf/选择性 JSON 分别为 12.77/12.26 µs，tcp-heavy 为 4.14/4.16 µs。这是组件微基准，不是 CONNECT/ext_proc 请求延迟，也不是完整网关吞吐。

较多转义字符的 Header 值虽然被选择性解析器跳过，仍需要被 JSON 扫描器遍历；escaped 样本的值是重复的 `a"\b`，序列化后约 1.62 MB，属于合法的合成压力样本，不代表生产中的常见比例。接收成本从未转义的 0.141 ms 增至 2.615 ms；跳过字段不能让扫描成本消失。

内存另起进程测试，四组样本、四种存储方式、三轮重复，每个进程保留 128 份独立编译结果，用 macOS `/usr/bin/time -l` 获取整个进程的最大 RSS。`json_value_retained` 额外长期保留完整 Value 树；其他三种只保留编译结果。输入 JSON/protobuf 缓冲区仅各保存一份，未模拟每个资源另存原始字节；不是 128 个 Sandbox 共享同一个 SP 的场景。

| 128 份策略的进程峰值 RSS，中位数 MiB | protobuf | 选择性 JSON | Value 转换后释放 | Value 长期保留 |
| --- | ---: | ---: | ---: | ---: |
| typical | 9.55 | 9.92 | 10.53 | 102.81 |
| tcp-heavy | 43.94 | 44.33 | 45.89 | 286.86 |
| http-heavy | 8.00 | 8.22 | 10.20 | 270.86 |
| http-heavy-escaped | 10.55 | 10.80 | 12.80 | 273.22 |

峰值 RSS 包含测试进程、输入缓冲区、临时解析对象和编译对象，不能直接当作纯缓存大小，也不能在不同样本间简单相减推算每条规则内存。同一组中，选择性 JSON 与 protobuf 相近；长期保留完整 Value 树代价明显，例如 http-heavy 为约 271 MiB，而选择性 JSON 约 8.2 MiB。

结论：完整 JSON 可以将额外成本限制在配置更新阶段，但 Porter 应直接反序列化必要字段并缓存编译结果。普通样本更新成本为几十到几百微秒，大型转义负载可达到数毫秒；批量更新和首次大量加载需要纳入容量评估。不要在每条 CONNECT 中重新解析 SP，也不要在没有用途时长期缓存完整 JSON 对象树。HTTP action 变化仍会引发 JSON 接收/投影，本次未实现跳过等价更新。

本次共 210 组计时阶段结果、48 次独立内存进程运行。新 bench 的 release 执行、Clippy `-D warnings` 和格式检查通过。JSON 投影是有效样本的 bench 原型，不包含生产所需的全部 CRD/领域验证、身份校验、NACK/旧版本缓存管理；未测 JSON xDS 端到端链路、gRPC 编解码和压缩、更新时连接争用、Linux jemalloc、EPE、海量资源/启动风暴。不能据此声称完整 JSON 已经接入 Porter 或得到完整产品性能验证。

复测：

```bash
go run extensions/porter/tests/sp_json_fixtures.go /tmp/porter-sp-fixtures.json
PORTER_SP_FIXTURES=/tmp/porter-sp-fixtures.json cargo test --release --locked \
  --manifest-path extensions/porter/Cargo.toml --test sp_json_benchmark \
  -- --ignored --nocapture --test-threads=1
```

原始 fixtures、五轮日志、逐轮结果、统计脚本、内存日志和环境信息位于本地验证 artifacts 的 `porter-sp-json-bench/`；`run.py` 顺序完成五轮计时和四组内存测量。单组内存复测需先将对应 fixture 单独写成只有一项的数组，通过 `PORTER_SP_MEMORY_MODE=protobuf|json_selective|json_value|json_value_retained` 和 `PORTER_SP_RETAIN=128` 运行同一测试二进制，并使用系统 time 记录峰值 RSS。

## 2026-11-07：共享 SecurityProfile 引用与 Sandbox 内嵌的 Kind 验证

在 `ssh my-ecs` 的独立 Kind 集群 `sp-tcp-review` 部署当前工作树编译的 Agentiod、Porter、EPE；保留既有 Envoy/SNI 模块与 ztunnel 镜像。Workload 使用有序 SecurityProfile 引用，Sandbox 内嵌包含 SNI/TCP 策略的 SecurityProfile。其他 Kind 集群未修改。

| 验证组 | 结果 |
| --- | --- |
| HTTP/TLS/raw TCP、SNI、解析后地址、TrafficPolicy 的原有流量矩阵 | 32/32 |
| 热更新、非法更新保留有效版本、共享与内嵌优先级等原有变化用例 | 9/9 |
| 共享资源更新、引用滞后、删除、UID 重建、NACK、断线恢复等断言 | 29/29 |
| Sandbox 运行时与正常删除重建探测 | 范围内 7/7；另有 1 项人为写入错误控制器状态的边界观测，不作为本轮验收失败 |
| 正常删除重建时的连续连接 | 两个 Workload，5 轮删除/重建，360 次新 TCP 连接，0 次失败；仅代表本轮观测 |

故障注入使用两个测试 ADS 中转，分别置于 Porter、EPE 与真实 Agentiod 之间。中转可暂停指定类型的下游响应、注入一次非法 SP 或删除通知，以及拒绝重连。暂停期间代为 ACK 上游响应，避免将 Agentiod 的 ACK 超时误当成客户端策略行为；解除暂停后过滤已代 ACK 的 nonce。中转与脚本仅保留在测试目录，未加入产品代码。

确认的行为：

- 两个 Workload 共享同一 SP。只改策略内容时，两边的决策都更新，WDS 的内容版本保持不变。
- 相邻同 action、同端口条件的 SNI 域名会合并；中间的 wildcard deny 保持顺序，后面的 passthrough 不会越过它。
- 非法 SP protobuf 触发 Porter NACK，上一份完整配置仍生效，之后的有效更新可以恢复。
- 下游 WDS 被暂停、SP 删除通知先到时，Porter 拒绝新 CONNECT；释放 WDS 后，根据新的引用链恢复。
- 同名 SP 重建、UID 变化，而 WDS 仍引用旧 UID 时拒绝；新 WDS 到达后恢复。冷加载缺失 SP 时也不会当成空策略放行。
- EPE 的 Kubernetes watch 已收到删除、WDS 仍持有引用时，60 秒内继续执行旧 block，返回 403；65 秒后返回 503；释放 WDS 后返回 200。
- Porter ADS 断开后，已预热的缓存可在断线宽限期内使用；过期后新连接失败，恢复连接并重新发现资源后恢复。此项是完整网关链路观测，受 Pod readiness 和 Service 端点状态影响，不用于精确测量 5 秒边界。

**范围外边界观测：人为写入错误的 Sandbox 宿主绑定。**

旧现场未调用 `PrepareSandbox`，曾依赖将 Sandbox 规则投影进宿主 WDS。新结构去掉该投影后，必须先完成真实 Sandbox 注册；本次调用 `agentio.network.v1.SandboxNetwork/PrepareSandbox`，使用 `kruise:review-inline`，验证注册后内嵌 TCP deny 正常生效。

随后将 Sandbox `status.podInfo.podUID` 改为一个不属于该 Sandbox 的 Pod UID。控制面撤销其 attester，ztunnel admin 中 `sandboxes` 变为空；原本被内嵌规则拒绝的 TCP 9001 三次均返回 `SERVER-FIRST`。恢复原始 podUID 后，最终完整流量矩阵重新 32/32 通过。此现象与 ztunnel 将 `ready_sandbox()` 的 `NotReady` 映射为不携带 Sandbox 上下文一致：网关只看到 Workload，无法执行已消失的 Sandbox 内嵌规则。

本轮信任 Sandbox 控制器维护正确的宿主绑定，不将人为篡改其 status 字段造成的错误状态作为 SP 下发方案的阻塞项。上述测试保留为异常控制面输入的边界记录，原始结果中的失败断言不改写。它没有证明正常 Sandbox 创建、Pod 重建或合法绑定迁移也会出现同样的中间状态；只有这些受支持的生命周期能够到达该状态时，才需要将其纳入对应的正确性要求。本轮不为这项范围外输入修改 ztunnel。

测试工具的两项修正保留了原始记录：初始测试证书错误地带有 CA 属性，修正为独立 CA 签发的服务端证书后继续；初版中转暂停 WDS 时未代 ACK，触发连接重建，曾观测到 500。补齐 ACK 后重新完整验证，EPE 宽限期过期的最终结果为 503，500 不计为产品缺陷。

远端现场：`/root/agentio-sp-tcp-review-20261106/profile-delivery-20261107/`。`results/summary.json` 是汇总；`lifecycle-latest.json`、`sandbox-and-churn.json`、`churn-samples.json` 保存逐项结果；`results/final-state/` 保存 Pod、策略、Deployment、Envoy 配置、Porter metrics、ADS 中转状态和镜像 ID；`logs/` 保存全部运行记录。中转最终处于直通状态，暂停和拒绝重连均已解除，集群和测试对象保留。

复测先设置 `KUBECONFIG=/root/agentio-sp-tcp-review-20261106/kubeconfig`。父目录的 `run.py` 只发流量；`transitions.py`、本目录的 `lifecycle.py` 和 `sandbox-and-churn.py` 会修改测试策略或绑定。运行变更脚本应顺序执行。上述范围外的 Sandbox 边界场景可由 `sandbox-and-churn.py` 复现，脚本在结束时恢复原规则和绑定。

未覆盖 IPv6/UDP、多节点、多 Sandbox 共享宿主和规模压力；不声称验证混合版本升级或生产环境的无中断发布。

## 2026-11-07：实际 Porter 引用实现的性能对照

本节测实际引用版与远端保留的、切换引用前的内嵌版，区别于前面的下发模型原型。未修改保留的 Kind 现场。在 my-ecs（Intel Xeon 6982P-C、32 vCPU、约 60 GiB）以 release/thin-LTO、Linux jemalloc 运行，测试进程绑到 CPU 4–7，Tokio 使用 4 个 worker。主机未独占；两版及共享/独立拓扑交替运行 5 轮，以降低顺序和宿主噪声影响。

使用真实 TLS ADS 和 ext_proc gRPC，规则目标命中最后一条 allow；相同证书、20 个 Workload 标签、固定总共 8 条 SNI。引用版真实携带 1、8、32 个 SP，并非将多个逻辑 SP 仍合并成一个资源。每轮每组测 100 个冷 Workload，热路径各约 5000 次 handler、gRPC C1、gRPC C16；总计 20 个进程、490 条阶段结果、1,499,200 次计时热请求，全部响应断言通过。表中是 5 轮请求 P50 或吞吐的中位数，不是完整网关压测。

| SP 数 / TCP 总规则数 | 热 handler P50 µs：内嵌 → 引用 | gRPC C16 RPS：内嵌 → 引用 | 吞吐变化 |
| --- | ---: | ---: | ---: |
| 1 / 0（仍有 8 条 SNI） | 6.80 → 7.15 | 40,257 → 39,982 | -0.7% |
| 1 / 16 | 6.92 → 7.18 | 40,296 → 39,878 | -1.0% |
| 8 / 128 | 7.35 → 8.96 | 39,787 → 37,809 | -5.0% |
| 8 / 1024 | 10.13 → 11.69 | 37,743 → 36,149 | -4.2% |
| 32 / 1024 | 10.16 → 15.47 | 37,479 → 31,810 | -15.1% |

32 SP 的 gRPC C16 P99 为约 613 → 737 µs。引用增加逐请求的名字复制、共享缓存读取、Arc 快照及身份配对检查；本节没有细分每部分的占比。1 SP 的总 gRPC 差异较小，8 SP 有小幅代价，32 SP 的下降已经明显，不能将该实现概括为完全没有热路径回退。

| SP 数 / TCP 总规则数 | Workload、SP 都未缓存，P50 µs：内嵌 → 引用 | SP 已缓存、Workload 未缓存，P50 µs：内嵌 → 引用 |
| --- | ---: | ---: |
| 1 / 0 | 49.4 → 93.3 | 49.1 → 47.4 |
| 1 / 16 | 56.7 → 98.1 | 56.8 → 47.4 |
| 8 / 128 | 96.7 → 169.2 | 96.1 → 50.2 |
| 8 / 1024 | 429.4 → 465.4 | 431.5 → 54.8 |
| 32 / 1024 | 387.6 → 478.5 | 400.3 → 61.9 |

这些是 loopback ADS 延迟。完全冷加载需要先取得 WDS，再并行请求其中的 SP，因此多一轮发现；SP 已缓存的连接不会远程查询它们。真实 ADS RTT 会影响完全冷加载的代价，本节不从 loopback 推算跨节点绝对延迟。

另以生产 `Client.apply` 测同一有效规则名称更新的接收、解码、编译、发布和旧对象释放：101 个 Workload 共用一组 SP，内嵌版重放 101 份 WDS，引用版只更新其中一份 SP，重复 20 次；计时不含更新构造、控制面编译、ADS 传输或并发请求。基准副本仅将私有 `apply` 改为公开以便调用，产品代码未增加接口。

| SP 数 / TCP 总规则数 | 更新 apply P50 µs：内嵌 → 引用 |
| --- | ---: |
| 1 / 16 | 525.98 → 5.07 |
| 8 / 128 | 2943.33 → 4.91 |
| 8 / 1024 | 24337.98 → 24.08 |
| 32 / 1024 | 23030.33 → 7.69 |

两份实际库分别强制重编译、复制为独立测试二进制，并在每个进程核对是否包含 SecurityProfile 资源支持，避免共享 Cargo target 复用另一份源码的旧产物。原始输入、源码副本、构建日志、交替执行脚本、20 份运行日志、逐轮结果与汇总保留于远端 `/root/agentio-sp-tcp-review-20261106/profile-reference-perf-20261107/`；本地 artifacts 的同名目录保存结果和两份 bench 快照。`results/report.txt` 是紧凑对照表，`results/summary.json` 含每项指标的五轮中位数及范围。

本节支持继续采用引用设计，但几十个 SP 的热路径成本应单独评估。尚未测 Sandbox 分支、IPv6、缓存淘汰压力、更新与请求并发、生产规模内存，以及 Envoy/EPE 完整网关吞吐；没有据此新增预绑定、反向依赖或请求快照缓存。

## 2026-11-07：策略正文依赖与 Workload 最小消费投影的控制面基准

本节比较真实 Go Compiler/KRT 图的三种依赖方式，回答是否应保留 `securityAttachments`，以及其他策略是否也值得迁移。生产代码未因本次性能评估而修改；候选改动仅存在于独立源码副本和 Go overlay 中，保留的 Kind 集群未变更。

三种方式：

- `full`：SP、TrafficPolicy、EgressPolicy 都从完整编译结果生成 Workload 策略；SP 直接读取 `compiled.Attachment.UID`。已有 attachment collection 仍用于选择和排序。
- `current`：当前实现。SP 从 attachment 获取 UID；TrafficPolicy 读取完整编译结果及 `AsAuthorization`；EgressPolicy 读取有效策略内容。
- `projected`：SP 保持当前方式；TrafficPolicy 增加每份共享策略的最小 WDS 消费投影，仅含名称、UID 和具有 Workload scope 的授权引用名称。EgressPolicy 保持正文依赖，因为正文需要写入 WDS，不能用 attachment 替代。

环境为 `ssh my-ecs`，Intel Xeon 6982P-C，Go 1.26.8 linux/amd64，`GOMAXPROCS=4`，测试进程绑 CPU 4–7，宿主未独占。相同的真实 Compiler 图中，每个 Workload 同时绑定一份 SP、一份 TrafficPolicy 和一份 EgressPolicy。SP 含 16 条 TCP 规则及 8 条 TLS 输入规则，TrafficPolicy 含 16 条规则；另测 1,000 Workload、48 条规则的敏感性组。规模为 1、100、1,000、10,000 个 Workload。三版交替运行五轮，共 375 组测量、4,875 次源策略更新。

计时包含源更新后的校验、编译、KRT 传播、Workload 策略生成、相等性比较及应有的资源编码；源对象构造、初始加载、Kubernetes watch、DNS 网络和 ADS 发送不在更新计时内。`testing/synctest.Wait` 仅作为传播完成屏障；墙钟通过 `CLOCK_MONOTONIC`、进程 CPU 通过 `getrusage` 读取，均为真实时间。每次源更新断言只编译一次，并核对 Workload 重算和 Address 输出事件数量。以下是每轮平均更新成本的五轮中位数，不是单请求 P50；分配量是累计新增分配，并非常驻内存。

### 正文更新

所有 SP/TCP 正文更新均不产生 Address/WDS 内容更新；差异来自是否遍历并重算引用它的 Workload。

| 更新对象 | 共享 Workload 数 | CPU ms/次：完整依赖 → 投影 | 新增分配 MiB/次：完整依赖 → 投影 | Workload 重算/次 |
| --- | ---: | ---: | ---: | ---: |
| SP TCP 正文 | 100 | 1.537 → 0.090 | 0.632 → 0.034 | 100 → 0 |
| SP TCP 正文 | 1,000 | 11.707 → 0.089 | 6.005 → 0.034 | 1,000 → 0 |
| SP TCP 正文 | 10,000 | 143.205 → 0.141 | 59.420 → 0.049 | 10,000 → 0 |
| TrafficPolicy 正文 | 100 | 1.606 → 0.107 | 0.684 → 0.056 | 100 → 0 |
| TrafficPolicy 正文 | 1,000 | 12.598 → 0.106 | 6.344 → 0.056 | 1,000 → 0 |
| TrafficPolicy 正文 | 10,000 | 144.381 → 0.159 | 62.635 → 0.068 | 10,000 → 0 |

1 个 Workload 时，SP 正文更新为 0.129 → 0.094 ms CPU，TrafficPolicy 正文更新为 0.138 → 0.106 ms CPU，收益较小。1,000 Workload、48 条规则时，SP 为 11.503 → 0.111 ms，TrafficPolicy 为 12.887 → 0.151 ms，说明该组的大部分额外成本来自 Workload 扇出，而非规则数量。

对应 10,000 Workload 的墙钟更新传播成本：SP 为约 95.7 → 0.109 ms，TrafficPolicy 为约 99.3 → 0.113 ms。SP 完整依赖的五轮 CPU 范围是 139.0–146.7 ms，当前 attachment 方式为 0.124–0.156 ms；TrafficPolicy 当前方式为 136.4–149.9 ms，最小投影为 0.155–0.181 ms，差距明显大于轮次波动。

### 不能省略的更新

| 10,000 Workload 的更新 | CPU ms/次：full / current / projected | Address 更新数/次（各版相同） |
| --- | ---: | ---: |
| EgressPolicy CIDR 正文 | 496.9 / 507.1 / 504.1 | 10,000 |
| SP UID 替换 | 542.6 / 553.1 / 548.6 | 10,000 |
| TrafficPolicy 增删 ingress 授权引用 | 496.9 / 503.7 / 496.9 | 10,000 |

这些变化确实改变 Workload 输出，各版均保留必要的重算和下游资源更新。投影的效果是拦截与消费者输出无关的正文变化，没有把必要更新过滤掉。 候选投影版还通过了全部既有 Compiler 单元测试（跳过本次显式启用的性能测试）；日志保存在 `logs/functional-projected-all.log`。

### 初始化与常驻堆

以下用每轮第二个场景的初始化指标，避开首次 protobuf 预热。

| Workload 数 | 初始化墙钟 ms：current → projected | GC 后新增堆 MiB：current → projected |
| --- | ---: | ---: |
| 1,000 | 33.98 → 34.08 | 10.261 → 10.263 |
| 10,000 | 350.46 → 347.56 | 98.371 → 98.423 |

本组没有看到明显的初始化或常驻内存回退；这不等价于任意策略数量、标签规模下的内存上界。

### 建议

保留 SP 的 attachment 依赖，不建议为了字段表面一致而退回完整正文依赖。进一步统一时，应统一为“按 Workload 实际消费内容投影”：SP 消费绑定元数据；TrafficPolicy 消费 UID 和授权引用名称；EgressPolicy 消费有效策略正文。TrafficPolicy 的最小投影在共享策略频繁更新时有明确收益，值得作为后续迁移方向；不是给每种策略都新增一个 attachment 字段。

该建议取代本节之前基于未量化成本提出的“可以先删掉 SP 专用字段”的倾向。低共享度、低更新频率场景的绝对成本较小；本次结果不能直接换算成 Porter 请求吞吐变化。

尚未覆盖 Kubernetes/ADS 端到端延迟、生产更新频率和并发多策略更新；基准使用 3 个标签、每个 Workload 绑定一份各类共享策略。源代码副本、三个 overlay、三份独立测试二进制、五轮日志与原始 JSON 保留在远端 `/root/agentio-sp-tcp-review-20261106/policy-dependency-perf-20261107/`，本地对应 artifact 目录保存 fixture、源文件快照、overlay、脚本和结果；`results/summary.json` 包含每项的五轮中位数及范围。

### 评估后的实现落地

TrafficPolicy 的 Workload 消费路径已迁移到 `trafficWorkloadBinding`，仅保留名称、UID 和 Workload scope 的授权引用名称。SP 继续读取 attachment，EgressPolicy 继续读取有效正文。正文变化更新共享策略资源；UID 或授权引用名称变化才触发相应 Workload 引用更新。

新增真实 Compiler/KRT 依赖测试，验证正文变化完成编译但不重算 Workload，UID 和 ingress 授权引用变化只重算绑定的 Workload。`go test ./pkg/compiler ./pkg/policy ./pkg/xds` 全部通过，更新后的 `BenchmarkWorkloadPolicyProjection` fixture 也通过单次运行检查。本次未重新部署 Kind，也未重跑前述五轮性能对照。
