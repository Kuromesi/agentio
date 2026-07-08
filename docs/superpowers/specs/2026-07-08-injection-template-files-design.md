# 注入模版文件化（对齐 Istio 社区）设计

## 背景

当前 sidecar-injector configmap 的所有注入模版（`ztunnel`、`waypoint`）连同 config 骨架字段一起塞在单个
`manifests/charts/agentio/files/injection-config.yaml` 里，由 `templates/injection-templates.yaml`
通过 `.Files.Get "files/injection-config.yaml" | indent 4` 整体读入。

Istio 社区 chart 的做法是：每个注入模版单独成文件放在 `files/`，configmap 模版负责内联渲染
config 骨架，并按模版名把各文件用 `.Files.Get ... | trim | indent` 逐个注入到 `templates:` 下。

本设计将 agentio chart 对齐该风格。

## 目标

- 每个注入模版独立成文件，命名 `<name>-injection-template.yaml`。
- configmap 模版内联渲染 config 骨架，按模版名区分注入。
- 渲染出的最终 configmap 内容与改造前**完全等价**。

## 非目标

- 不改动 `values:` JSON 块、`agentio-config.yaml`、webhook、`values.yaml`。
- 不新增/删除模版种类，不改模版 body 语义。

## 变更详情

### 1. 拆分模版文件

| 新文件 | 来源 |
| --- | --- |
| `files/ztunnel-injection-template.yaml` | 原 `injection-config.yaml` 中 `templates.ztunnel` 的 body（约第 11–363 行），整体左移到 column 0 |
| `files/waypoint-injection-template.yaml` | 原 `injection-config.yaml` 中 `templates.waypoint` 的 body（约第 364–772 行），整体左移到 column 0 |

删除 `files/injection-config.yaml`。

### 2. 重写 `templates/injection-templates.yaml` 的 `config` 块

`data.config` 由「一把梭读整文件」改为「内联骨架 + 逐模版注入」：

```yaml
  config: |-
    defaultTemplates: [ztunnel]
    policy: enabled
    alwaysInjectSelector:
      []
    neverInjectSelector:
      []
    injectedAnnotations:
    template: "{{`{{ Template_Version_And_Istio_Version_Mismatched_Check_Installation }}`}}"
    templates:
      ztunnel: |
{{ .Files.Get "files/ztunnel-injection-template.yaml" | trim | indent 8 }}
      waypoint: |
{{ .Files.Get "files/waypoint-injection-template.yaml" | trim | indent 8 }}
```

`values:` 块及 configmap 其余部分保持不动。

## 关键约束

- 模版 body 里的 `{{ ... }}` 由注入器运行时（K8s admission）解析，非 Helm。`.Files.Get` 读入不触发
  Helm 求值，因此拆分安全，与现状 `.Files.Get` 整个文件行为一致。
- config 骨架里的 `template: "{{ Template_Version_And_Istio_Version_Mismatched_Check_Installation }}"`
  从「文件内（不被 Helm 解析）」移到「configmap 模版内联」后会被 Helm 当作 action，必须用
  `` {{`...`}} `` 转义为字面量。

## 验证

改造前后各跑一次 `helm template`（开启 `sidecarInjector.enabled`），对比 `*-sidecar-injector`
configmap 的 `data.config`，要求两者语义等价（仅允许 trim 引入的首尾空白差异）。
