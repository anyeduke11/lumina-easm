# Lumina 当前态架构资料包

本目录是对仓库 **当前实现（as-is）** 的一次证据化架构分析，基线为 `v0.0.2`（2026-10-20）。

它回答的问题只有一个：**今天的 Lumina 由哪些进程、域、状态机、数据域与外部接缝组成，它们如何协作，哪些结论有代码证据、哪些仍是目标态或未知项。**

> 目标态方案在 `../EASM-ARCH-OPT-v1.1.md`，请勿把目标态描述当作当前实现。两者的对照见 `architecture-understanding.md` §9。

---

## 阅读顺序

| 顺序 | 文件 | 回答什么 | 适合谁 |
| --- | --- | --- | --- |
| 1 | [architecture-understanding.md](architecture-understanding.md) | 全仓库当前态架构：形态、参与者、进程、域地图、状态机、三重门、权限边界、能力接缝、未知项 | 所有人 |
| 2 | [system-context.structurizr.dsl](system-context.structurizr.dsl) | C4 系统上下文 + 容器视图（Structurizr DSL） | 架构师、负责人 |
| 3 | [module-map.dot](module-map.dot) | 48 个 internal 包的主干依赖、集群与可选 Provider | 后端、评审者 |
| 4 | [flow-closed-loop.dot](flow-closed-loop.dot) | 一条线索从授权 → 采集 → 三重门 → 处置 → 复测的闭环 | 安全运营、测试 |
| 5 | [system-model.evidence.md](system-model.evidence.md) | 上述结论的逐条出处（文件:行）与置信度 | 需要核对证据的人 |

**建议读法**：先读 `architecture-understanding.md` 的 §0–§6，建立心智模型；再看两张图确认空间结构（模块）与时间结构（流程）；最后按需查证据索引。

---

## 产物说明

| 文件 | 性质 | 源/派生 |
| --- | --- | --- |
| `architecture-understanding.md` | 当前态分析报告 | 源（人工维护） |
| `system-context.structurizr.dsl` | C4 模型源文件 | 源（Structurizr DSL） |
| `module-map.dot` | 模块依赖图源文件 | 源（Graphviz DOT） |
| `flow-closed-loop.dot` | 业务闭环图源文件 | 源（Graphviz DOT） |
| `system-model.evidence.md` | 证据索引 | 源（人工维护） |
| `*.svg`（可选） | 渲染产物 | 派生，不手工编辑 |

**事实源优先级**：代码/迁移 > 脚本/测试 > 仓库文档 > 仓库外文档。图表只表达结论，不产生事实；结论冲突时回到证据索引与源码。

---

## 如何打开与渲染

### Structurizr DSL

- 在 Qoder 中直接打开 `system-context.structurizr.dsl`，使用 Structurizr DSL 查看器预览；
- 或粘贴到 Structurizr Playground / 使用 Structurizr CLI 渲染（需要本地已安装对应工具）。

### Graphviz DOT

本机当前未安装 `dot`（渲染前先确认）：

```bash
command -v dot || brew install graphviz
dot -Tsvg docs/architecture/current-state/module-map.dot -o docs/architecture/current-state/module-map.svg
dot -Tsvg docs/architecture/current-state/flow-closed-loop.dot -o docs/architecture/current-state/flow-closed-loop.svg
```

若暂时不渲染，DOT 源文件仍可在 Qoder 的 DOT 格式查看器中打开。图中使用了 `PingFang SC` 字体以正常显示中文；在非 macOS 环境渲染时可按需替换为 `Noto Sans CJK SC`。

---

## 范围与口径

- **包含**：进程与装配、领域包、数据模型与状态机、鉴权/数据域/审计、关键业务闭环、Provider 接缝、前端与验证基线。
- **不包含**：字段级 API 契约、逐表 DDL 评审、性能实测、渗透测试、目标态迁移任务拆分。
- **当前态与目标态分离**：`EASM-ARCH-OPT-v1.1.md` 只作为对照，不作为“已实现”证据。
- **置信度**：高/中/低/未知，定义见 `system-model.evidence.md` 开头。

---

## 维护与复算

代码演进后，优先更新 `system-model.evidence.md`，再同步报告与图源，避免“图先变、证据后补”。常用复算命令：

```bash
# 构建与静态检查
make build test vet trace

# PG 集成（需要 easm_app DSN；不要与清场 SQL 并发）
EASM_PG_DSN='postgres://easm_app:***@127.0.0.1:5432/easm?sslmode=disable' make test-integ

# 包依赖矩阵
go list -f '{{.ImportPath}}|{{join .Imports ","}}' ./platform/services/internal/...

# RLS 覆盖
grep -rn "ENABLE ROW LEVEL SECURITY" migrations/
```

**已知的维护注意点**：

1. `ledger.Item` 增字段必须同步“迁移列 + Create + Update + scanLedger”，否则 PG 模式静默丢字段（`pgstore/ledger.go:20-22`）。
2. RLS 目前只覆盖 8 张表；新增直连 SQL 的入口必须显式带数据域过滤。
3. `tenant` 与 `entity` 是同一数据域的双术语；对外 API 用 `entities` 别名，内部仍用 `tenant_id`。
4. live 脚本默认假设 `:18080`，而 `config.Load()` 默认端口为 `8087`；运行前先对齐。
5. CI 已补齐四门禁（`.github/workflows/ci.yml`：unit / migrate+PG integration / OpenAPI / trace+lint）；远端实际执行状态仍以 GitHub Actions 为准。

---

## 分析基线

- 仓库：`Lumina`（本地工作树；公开远端 `anyeduke11/lumina-easm`）
- 提交：`v0.0.2` 发布提交（2026-10-20）
- 日期：2026-10-20
- 方法：只读分析（未修改业务代码）；证据来自源码、迁移、脚本、前端与仓库文档。
