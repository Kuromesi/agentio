# Substrate ListWorkers PoC 实施计划

1. 添加最小 `ateapi.Control/ListWorkers` proto，并扩展 Agentio proto 生成脚本。
2. 先编写分页、字段校验、Pod UID 防重用、快照更新和失败保留旧快照的单元测试。
3. 实现 mTLS gRPC 客户端、轮询器、Actor 绑定缓存和 Controller 查询接口。
4. 给内部 WorkloadInfo 保存 Kubernetes Pod UID，在 WCDS 生成时优先查询 ListWorkers 数据源。
5. 在绑定快照变化时触发强制 xDS push。
6. 添加默认关闭的 Helm values、环境变量和 PodCertificate/ClusterTrustBundle 投影。
7. 运行 Agentio Controller、Ambient WCDS、xDS 和 Helm 聚焦测试。
8. 在 `ssh my-ecs` 的 `kind-substrate-poc` 集群部署，验证无需 Worker Actor labels 也能随 Actor 创建/删除更新 WCDS。
9. 把配置、命令、结果和限制补充到中文 PoC 文档，提交并推送 `codex/actor-context-poc`。
