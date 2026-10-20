# Lumina 烛隐 EASM · 当前态架构理解

> **性质**：当前态（as-is）架构分析，不是目标态设计。
> **基线**：`v0.0.2`，工作树分析日期 2026-10-20。
> **方法**：代码、迁移、前端、脚本与仓库文档交叉取证；所有关键结论在 [system-model.evidence.md](system-model.evidence.md) 有出处。
> **边界**：仓库外上位文档（PRD/SRS/详细开发计划）与目标态方案 `../EASM-ARCH-OPT-v1.1.md` 仅用于对照，不作为“当前已实现”的证据。
> **置信度**：高 = 代码/迁移直接可见；中 = 由多处间接证据推断；低 = 文档自述、尚未在代码中闭合；未知 = 仓库内无法验证。

---

## 0. 一句话结论

Lumina 是一个 **Go 单模块、以 PostgreSQL 为唯一必需外部依赖的模块化单体**：REST 与 MCP 双入口共享同一条鉴权链和同一组领域服务；PG 队列（`SKIP LOCKED`）与 Temporal 组成两条异步执行路径；**证据 WORM + 台账三重门 + 工单/通报状态机**构成“不造假”的治理内核；AI、MinIO、沙箱、向量库、Neo4j 等能力均为 **Provider 接缝**，未装配时用 501 或如实标注暴露边界，而不是静默降级。

它当前的重心仍是 **“发现 → 入账 → 处置 → 复测”的治理闭环**；资产身份/观察流/图谱（Phase 1–2）已经进入代码，但“持续 EASM 运营环”的完整形态仍在演进中（见 `EASM-ARCH-OPT-v1.1.md`，目标态）。

---

## 1. 规模与形态快照

| 维度 | 当前事实 | 证据 |
| --- | --- | --- |
| 语言/构建 | Go 1.24.0，单模块 `github.com/wangdev88/easm-platform` | `go.mod:1-3` |
| 外部依赖 | `lib/pq`、`minio-go/v7`、Temporal SDK；HTTP 用标准库 `net/http` | `go.mod:5-13` |
| 代码组织 | 48 个 `internal` 包 + 6 个 `cmd` 包 = 54 个 Go 包（与 `make trace` 的 54 包口径一致） | `ls platform/services/internal`、`ls platform/services/cmd` |
| 进程入口 | `server`、`jobworker`、`worker`，一次性 `migrate`/`passkey`/`breakglass` | `platform/services/cmd/*` |
| HTTP 面 | `internal/httpapi` 集中注册 118 处 `mux.Handle`；`/v1/*`、`/healthz` | `platform/services/internal/httpapi/server.go:226-356` |
| MCP 面 | `/mcp`，JSON-RPC 2.0，16 个工具，三级权限 | `platform/services/internal/mcp/server.go:150-260` |
| 数据模型 | 30 个迁移文件，34 张表；8 张表启用 RLS | `migrations/001-030`；`grep "ENABLE ROW LEVEL SECURITY"` |
| 业务口径 | 五阶段 P1–P5（步骤 4/4/5/3/4）；34 项敏感数据 / 22 条规则；图 13 类实体 / 11 类关系 | `sweep/sweep.go`、`classify/`、`graph/graph.go:18-57` |
| 对外版本 | v0.0.2（README/CHANGELOG 随代码维护） | `README.md`、`CHANGELOG.md` |

**形态判断**：这是一个 **modular monolith（模块化单体）**，不是微服务。每个域自带 `Store` 接口与内存实现，PG 实现集中在 `internal/pgstore`；进程间通过 PostgreSQL 与 Temporal 协作，而不是 RPC 网格。这个形态与“开发机无容器、PG 是唯一必需外部依赖”的本地化约束一致（`AGENTS.md`）。

---

## 2. 系统上下文与参与者

C4 系统上下文与容器视图见 [`system-context.structurizr.dsl`](system-context.structurizr.dsl)。

| 参与者 / 外部系统 | 与平台的关系 | 证据 | 置信度 |
| --- | --- | --- | --- |
| 安全运营人员（R1–R8） | 通过控制台/REST/MCP 执行排查、研判、工单、通报、报告 | `rbac/rbac.go:31-39`；`console/easm-live.js` | 高 |
| 平台管理员（admin/R7） | 实体数据域、授权、审计、告警出口 | `rbac/rbac.go:31,38`；`httpapi/server.go` | 高 |
| 被监管单位 / 租户（对外称 entity） | `entity_id` 是数据域；`/v1/entities` 是 `/v1/tenants` 的一等别名 | `httpapi/server.go:358-374` | 高 |
| 第三方平台（仓库/网盘/社交/暗市） | 工单投诉/删除申请的目标；平台只跟踪状态，不代执行 | `workorder/workorder.go:33-39`；`httpapi/workorder` | 高 |
| 公安 / 通报中心 | 通报材料接收方；平台生成材料，人工投递后回填回执 | `notice/notice.go:171-254` | 高 |
| 外部数据源 | crt.sh（CT）、DNS、ASM/Cloud 通用 feed、暗网 feed（当前为夹具） | `connector/*`；`darkweb/darkweb.go:2,42` | 高/中 |
| 扫描 CLI 工具 | gitleaks / nmap / ffuf 以子进程执行，平台不内置扫描实现 | `collect/collect.go:51`；`plugin/plugin.go` | 高 |
| OIDC IdP | 可选身份源（RS256/JWKS）；未配置时用 dev token / break-glass | `httpapi/server.go:378-401`；`config/config.go` | 高 |
| LLM Provider | SenseNova / OpenAI 兼容；三件套同设才装配 | `cmd/server/main.go:400-423`；`ai/` | 高 |
| 证据存储 | 本地文件或 MinIO/S3，WORM 语义 | `evidence/evidence.go:31-43`；`cmd/server/main.go:273-294` | 高 |
| Temporal | 可选工作流引擎；未配置时进程内同步回退 | `cmd/server/main.go:195-205`；`tdispatcher/` | 高 |
| Sandbox Verifier | 可选门3 Provider；未装配时复测端点 501 | `verifier/`；`main.go:296-312` | 高 |

**最重要的边界事实**：平台在“监管单位单用户”方向上收敛，但**内部仍保留 tenant 命名与 RLS 作为 entity 数据域的 legacy 实现**；对外 API 已提供 `entities` 别名。这不是未完成的半成品，而是有注释说明的兼容策略（`httpapi/server.go:358-362`）。读代码时要把 `tenant` 一律理解为“数据域/被监管单位”，而不是“多租户 SaaS 的租户”。

---

## 3. 运行时容器与部署形态

| 容器/进程 | 职责 | 必需依赖 | 证据 |
| --- | --- | --- | --- |
| `cmd/server` | REST `/v1/*`、MCP `/mcp`、console 静态面；进程内 `monitor` 定时循环；无 Temporal 时进程内同步执行排查 | 无（内存模式）或 PG | `cmd/server/main.go:61-545`；`app/deps.go:105-171` |
| `cmd/jobworker` | 消费 PG Job 队列；`connector → observation → inventory → graph`；`detect` 判敏；资产自动衰减 | **PG 必需**（为空直接 fatal） | `cmd/jobworker/main.go` |
| `cmd/worker` | Temporal activity worker；调用 `sweep.ExecuteInto` | **PG 必需**；Temporal 连接 | `cmd/worker/main.go` |
| `cmd/migrate` | 按 `schema_migrations` 应用迁移 | PG | `cmd/migrate/main.go` |
| `cmd/passkey` / `cmd/breakglass` | 一次性运维工具（passkey 凭据/break-glass 哈希） | 无/配置 | `cmd/passkey`、`cmd/breakglass` |
| PostgreSQL | 事实源；RLS 数据域；Job 队列；审计；证据元数据 | — | `pgstore/pgstore.go`；`migrations/` |
| 证据存储（file/MinIO） | 不可变证据对象 | file 默认；MinIO 可选 | `evidence/evidence.go` |
| Temporal | 可选编排；TaskQueue `easm-sweep` | 可选 | `tdispatcher/` |
| 静态控制台 | `console/` 单页；`app.js` 演示数据 + `easm-live.js` 实时水化 | 浏览器 | `console/index.html`、`console/easm-live.js` |

**装配方式**：没有 DI 框架。`cmd/server/main.go` 顺序构造 config → 存储 → 各域 Service → `app.Deps` → `Handler()`；`app.Deps.Handler()` 再组装 REST、MCP、console 三条出口（`app/deps.go:105-171`）。两条铁律：

1. **env 设了但装载失败一律 `log.Fatalf`**（fail loud），不静默降级；
2. **可选能力未装配时返回 501 + machine-readable code**，不返回空数据冒充成功。

---

## 4. 逻辑分层与域地图

完整的模块依赖见 [module-map.dot](module-map.dot)（`rankdir=TB`，实线=编译期 import，虚线=可选/未装配 Provider）。按职责可分为六层：

### 4.1 接入与组装

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `internal/app` | 组装根：把 30+ 个域服务注入 `httpapi`/`mcp`，并把 `/mcp`、`/v1/*`、console 分流 | `app/deps.go:51-171` |
| `internal/httpapi` | 全部 REST 路由、鉴权中间件、handler、错误映射 | `httpapi/server.go:226-404` |
| `internal/mcp` | JSON-RPC 2.0、工具分级（readonly/controlled/dangerous）、allow/deny 审计 | `mcp/server.go:38-40,150-260` |
| `internal/config` | env 集中装载/校验（AI/SOAR/OIDC/生产环境 dev token 等） | `config/config.go:101-242` |

### 4.2 发现与采集

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `sweep` | P1–P5 五阶段排查；授权闸、限速消费、台账反推去重 | `sweep/sweep.go:53-126,289-337,441-490` |
| `collect` | `scan:repo/port/dir`；CLI 子进程；输出归一为 `easm.candidate.v1` | `collect/collect.go` |
| `darkweb` | 暗网兜底（当前 fixture）；归属判定；线索包 `LPK-*` + WORM | `darkweb/darkweb.go:2,42` |
| `connector` | `seed`/`ct`/`dns`/`asm`/`cloud` Connector 契约与实现 | `connector/*` |
| `discovery` | Connector → Observation → Inventory → Graph 的编排；Job Worker 消费 | `discovery/` |
| `job` | 队列状态机 `queued/leased/running/succeeded/failed/dead/canceled`；幂等键/退避/死信 | `job/job.go:29-34` |
| `plugin` | 插件 8 字段契约、许可证护栏、CLI 子进程唯一形态 | `plugin/plugin.go` |
| `candidate` | 候选归一与去重 | `candidate/` |

### 4.3 资产、图谱与检测

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `asset` | 扁平资产清单（历史主表） | `asset/` |
| `ingest` | 资产入账即投影为图实体 | `ingest/` |
| `inventory` | 规范资产 + 别名 + append-only 观察流；状态机 `candidate/confirmed/active/stale/retired` | `inventory/inventory.go:29-33,251-270` |
| `graph` | 13 类实体、11 类关系；路径查询端口（内存 BFS / PG 递归 CTE） | `graph/graph.go:18-57` |
| `detect` | 复用 22 条判敏规则，从观察生成 Finding；高危 raise 告警 | `detect/` |
| `finding` | 10 态生命周期；`confirmed` 必须有证据，`closed` 必须有证据 | `finding/finding.go:28-40` |
| `alert` | 告警 open/ack/closed，幂等 `ALT-<sha12>` | `alert/` |

### 4.4 治理与交付闭环

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `ledger` | 台账四态 `open/doing/closed/notify`；门1/门2/门3；`closed` 必经 `Verify` | `ledger/ledger.go:20-23,254-305,413-456` |
| `projection` | `confirmed/verified` Finding → 台账；严重级仍走门1/门2 | `projection/` |
| `workorder` | 五态工单 + 唯一跟催回退边；终态锁定；必挂同租户真实台账条目 | `workorder/workorder.go:33-39,194` |
| `notice` | 通报 `NB-<sha12>`；公安 24h/通报中心 48h；材料哈希；回执锁定 | `notice/notice.go:171-254` |
| `report` | 报告中心；MD / JSON / PDF 导出；材料证据化 | `httpapi/report.go:73-78` |
| `evidence` | WORM Store 接口（Put/Get/RefOf/Kind）；租户路径校验 | `evidence/evidence.go:31-43` |
| `verifier` | 门3 复测 Provider：HTTP 沙箱或本机命令 | `verifier/` |
| `monitor` | 进程内定时监控循环；排查任务单 `RT-<sha12>` | `monitor/monitor.go:126-152`；`monitor/task.go` |
| `notify` | Webhook / SMTP / SOAR 三通道；三闸门（高危/去重/失败上浮） | `notify/` |
| `evalset` | 评测集、指标、放量门禁、误报样本回流 | `evalset/` |

### 4.5 知识与 AI（辅助，不裁决）

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `vuln` / `intel` / `ownership` | 漏洞库、情报、归属判定 | 各自包 |
| `classify` | 22 条判敏规则（确定性） | `classify/` |
| `scoring` | 四因子评分（权重/阈值可注入） | `scoring/` |
| `secret` | 凭据有效性三档与五状态；`valid` 才连 `leaks` 边 | `secret/` |
| `shadowit` | 影子 IT 收敛建议 + 纳管人审 | `shadowit/` |
| `ai` | Provider 端口；AI 结论不入台账 | `ai/` |
| `mm` | 多模态判敏；`mm_*` 非破坏富化 | `mm/` |
| `usage` | 按租户 token 计量与月度预算告警 | `usage/` |

### 4.6 平台基座

| 包 | 职责 | 关键证据 |
| --- | --- | --- |
| `rbac` | 权限常量与角色矩阵（admin/R1–R8）；`InScope` | `rbac/rbac.go:31-56` |
| `audit` | 仅追加审计日志（allow/deny） | `audit/` |
| `authn` | dev token / OIDC RS256-JWKS / break-glass / passkey step-up | `authn/`；`httpapi/server.go:378-401` |
| `authz` | 授权单 Scope：域名/CIDR/端口/排除/时间窗/限速/二次授权/签署人/文档哈希 | `authz/authz.go:26-41` |
| `confirm` | 一次性高危动作确认（`X-EASM-Confirmation`） | `httpapi/confirm.go:50-59` |
| `tenant` | 实体数据域（legacy tenant） | `tenant/` |
| `pgstore` | 各域 Store 的 PG 实现；RLS GUC；`SKIP LOCKED` | `pgstore/pgstore.go:39-55` |

---

## 5. 数据模型、状态机与权限边界

### 5.1 双后端：内存 ↔ PostgreSQL

`PGDSN` 为空时，各域使用 `NewMemStore()`（单测/演示）；设置后由 `pgstore.Open` 统一替换存储，并挂上仅 PG 侧能力。风险点不在“有没有两套实现”，而在**两套实现的字段同步**：

- `ledger` 的 PG 实现是**显式列**而非 JSONB；`Item` 新增字段必须同步“迁移列 + Create + Update + `scanLedger`”四处，否则内存测试通过、PG 运行期静默丢字段/500。代码注释已把这条教训写入（`pgstore/ledger.go:20-22`）。
- 集成测试文件统一带 `*_integration_test.go` 和 `EASM_PG_DSN` skip 守卫；普通 `go test ./...` 不覆盖真 PG，必须跑 `make test-integ`。

### 5.2 状态机清单

| 对象 | 状态 | 约束 | 证据 |
| --- | --- | --- | --- |
| 台账 Item | `open → doing → closed`；`notify` 旁路 | `closed` 不能直接设置，必须经 `Verify` | `ledger/ledger.go:20-23,376-456` |
| 工单 | 待整改 → 处置中 → 已通报平台 → 已下架 → 已处置 | 唯一回退边“已通报平台→处置中”（跟催）；终态锁定 | `workorder/workorder.go:33-39` |
| Finding | new/triaged/validating/confirmed/remediating/verified/closed/false_positive/risk_accepted/duplicate | `confirmed` 必带 `evidence_ref`；`closed` 仅 confirmed/verified 且有证据 | `finding/finding.go:28-40`；`finding/` |
| 资产 | candidate/confirmed/active/stale/retired | retired 必须给 reason；stale 可回升 active | `inventory/inventory.go:251-270` |
| Job | queued/leased/running/succeeded/failed/dead/canceled | 租约 + 幂等键 + 退避 + 死信 | `job/job.go:29-34` |
| 通报 | 待报送 / 已报送 | 回执号必填；首份回执锁定，不可覆盖 | `notice/notice.go:225-254` |
| 排查任务单 | pending / done | 同源 pending 收敛；done 终态 409；完成人必填 | `monitor/task.go` |
| 告警 | open / ack / closed | 幂等 `ALT-<sha12>` | `alert/` |

### 5.3 三重门（零误报的机械落点）

1. **门1（V-5）**：`Level=严重` 必须有 ≥2 个独立信源（`XChk`）；不足则降为“高”，留痕并写 `ledger.gate1_downgrade` 审计（`ledger/ledger.go:254-283`）。
2. **门2（V-10）**：`严重` 必须有已回答的反证（`Refute`：claim/outcome/evidence）；无回答降“高”，反证成立（confirmed）降“中”，均留痕（`ledger/ledger.go:285-299`）。
3. **门3（S-2）**：闭环必须经 `POST /v1/ledger/{id}/verify`；`reproduced` 必带 `evidence_ref` → closed；`refuted/inconclusive` → doing。未装配 verifier 时端点 501，禁止冒充闭环（`ledger/ledger.go:413-456`；`verifier/`）。

**关键架构事实**：门1/门2 在 `ledger.Create` 内统一执行，所有入账路径（sweep/collect/darkweb/projection）共用，旁路无门；门3 只发生在 `Verify`。这使“零误报”成为数据入口的不变量，而不是某个页面的提示。

### 5.4 权限、数据域与审计

- **认证链**：Bearer dev token → OIDC（RS256/JWKS）→ break-glass；全不中 401（`httpapi/server.go:378-401`）。`EASM_ENV=production` + dev token 拒绝启动（`config/config.go:235`）。
- **单用户模式**：`EASM_SINGLE_USER=1` 要求恰好一枚 dev token（admin，`*` 数据域）或 OIDC；多账号被显式拒绝（`cmd/server/main.go:534-540`；`config/config.go:126`）。
- **RBAC**：admin/R1–R8 的权限矩阵集中在 `rbac/rbac.go`；handler 再显式 `p.Can(...)` + `InScope` 做数据域过滤。
- **数据域隔离**：`/v1/entities` 重写为 `/v1/tenants`，内部继续用 `tenant_id` 列与 RLS；PG 事务内 `set_config('easm.tenant_id', ...)`（`pgstore/pgstore.go:39-55`）。
- **RLS 覆盖是部分的（重要）**：当前只有 8 张表启用 RLS：`assets`、`findings`、`finding_validations`、`inventory_assets`、`inventory_aliases`、`inventory_observations`、`jobs`、`alerts`（`migrations/001,025,026,027,029`）。`ledger`/`workorder`/`notice`/`report` 等治理表依赖**租户范围 SQL + Service 层 `InScope`**，不是数据库 RLS。应用 DSN 必须是 `easm_app`（无 BYPASSRLS），否则 RLS 静默失效（`migrations/002_role_app.sql`；`AGENTS.md`）。
- **高危动作确认**：默认开启（`EASM_REQUIRE_CONFIRMATION=0` 显式关闭），`scan:port`/`scan:dir`/`notices` 需要一次性 `X-EASM-Confirmation`（先 `POST /v1/confirmations`），MCP `scan_active` 同闸（`confirmation_id`）；见 `httpapi/confirm.go`。
- **审计**：allow/deny 全量仅追加；MCP 调用同样审计（`mcp/server.go` 审计分支；`audit/`）。

---

## 6. 关键业务闭环（一图串起）

完整流程见 [flow-closed-loop.dot](flow-closed-loop.dot)。文字版：

1. **授权**：`authz.Scope` 固化授权书数字化形态（域名/CIDR/端口/排除/有效期/时间窗/限速/二次授权/签署人/文档哈希）。主动扫描与采集在进入工具前校验；`collect` 另有细目标 `CheckTarget` 和限速消费（`sweep/sweep.go:441-490`；`collect/collect.go`）。
2. **采集**：
   - `sweep` 按 P1–P5 对资产逐项检测，命中直接写台账；
   - `collect` 以 CLI 子进程跑 gitleaks/nmap/ffuf，输出归一为 `easm.candidate.v1`；
   - `darkweb` 从 fixture/feed 生成线索包；
   - `connector` + `discovery` 把外部观察写入 `inventory`（append-only），并投影到 `graph`。
3. **入账**：所有路径进入 `ledger.Create`，先过门1/门2；严重级结论必须有交叉信源和已回答的反证；证据 `raw_ref`/`snapshot_ref` 固化到 WORM。
4. **发现运营**：`detect` 从观察值命中 22 条规则生成 Finding；Finding 经 triage/validate 到 confirmed/verified；`projection` 把 confirmed/verified 投影为台账条目（P4、代码密码类/系统架构类、7 天 due），严重级仍受门1/门2 约束。
5. **处置与通报**：台账条目是工单/通报/报告的存在性前置（同租户真实条目）。工单五态跟踪至下架；通报生成材料哈希并锁定三要素，回执回填首份凭证不可覆盖；报告以台账为数据源导出 MD/JSON/PDF。
6. **复测闭环**：只有 `verify` 的 `reproduced` + `evidence_ref` 能把台账置为 `closed`；`refuted/inconclusive` 回到 `doing`。`closed` 是终态，当前实现没有 reopen 边；复发应新建 Finding/台账条目，而不是改旧账（`ledger/ledger.go:376-404,413-456`）。
7. **反馈与审计**：复测信号回流 `evalset`（误报样本/真阳性）；高危动作 allow/deny 全量写 `audit`。

**治理红线在代码中的表现**：

- 没有证据的“已修复”无法闭环（门3 + `Verification.Validate`，`ledger/ledger.go:101`）；
- 工单不能跳过“已通报平台”直接“已下架”（转移表拒绝）；
- 通报不能以不存在的或跨数据域的台账条目生成（`notice.Create` 先 `led.Get` + 同租户校验）；
- AI 不写台账、不裁决；MCP 高危工具与 REST 同闸，不因“AI 调用”获得特权。

---

## 7. 六条设计公理 → 代码落点

| 公理 | 当前落点 | 置信度 |
| --- | --- | --- |
| AX-1 数据是地基（图谱） | `graph` + `ingest.Projector`；资产入账即投影；`inventory` 观察流与图对接 | 高 |
| AX-2 确定性发现 + AI 判断（辅助、不裁决） | `classify` 22 规则为事实源；`ai` 仅 Provider 接缝；AI 结论不入台账 | 高 |
| AX-3 一切皆可验证 | `evidence.Store` WORM；`raw_ref`/`snapshot_ref`；门3 `Verification` 必须带证据；未装配 verifier=501 | 高 |
| AX-4 持续闭环 | 台账四态、工单五态、Finding 十态、资产五态；跳步/终态出边拒绝 | 高 |
| AX-5 人在环可审计 | 四类高危动作确认；notice 三要素锁定；audit allow/deny 全量；MCP dangerous 同闸 | 高 |
| AX-6 一切皆插件 | 平台零扫描逻辑；工具经 `plugin` 契约注册，CLI 子进程唯一执行形态；许可证护栏 | 高（代码契约）/中（实际插件生态尚小） |

---

## 8. 能力接缝与“未装配即边界”矩阵

| 能力 | 当前装配 | 未配置/未装配时的行为 | 证据 | 置信度 |
| --- | --- | --- | --- | --- |
| PostgreSQL | `EASM_PG_DSN` 设置即启用 RLS/持久化/队列 | 纯内存模式；部分端点能力降级 | `cmd/server/main.go:86-107` | 高 |
| Temporal | `EASM_TEMPORAL_HOST` 设置即装载 `tdispatcher` | 进程内同步执行排查 | `main.go:195-205` | 高 |
| 证据后端 | `EASM_EVIDENCE=file`（默认）/`minio` | 常量非 `file|minio` 即 fatal | `main.go:273-294` | 高 |
| OIDC | `EASM_OIDC_*` 完整才装配 | 仅 dev token / break-glass；生产禁用 dev token | `config/config.go:235-238` | 高 |
| AI | `EASM_AI_BASE_URL`/`MODEL`/`API_KEY` 三件套同设 | 全未设=相关端点 501；半设=fatal | `main.go:400-423` | 高 |
| Sandbox Verifier | `EASM_SANDBOX_URL` | 复测端点 501 `verifier_unavailable` | `main.go:296-312`；`verifier/` | 高 |
| 本机验证命令 | `EASM_VERIFY_CMD` | 未设则无本机复测 Provider | `main.go:296-312` | 高 |
| Neo4j | `graph.Neo4jHTTP` 存在，但未在装配根挂载 | 图后端仍为内存/PG | `graph/neo4jhttp.go`；`main.go` | 高（未装配） |
| 向量库 | 未配置 | MCP `knowledge_export` 如实标注 `vector_store=not_configured` | `mcp/server.go:219,476` | 高 |
| 真实暗网 feed | 当前 fixture | 保留入口，样例数据；真实源属外部项 G8-03 | `darkweb/darkweb.go:2,42` | 高 |
| ASM/Cloud feed | env 配置才注册 | 未配置不注册 Connector | `connector/`；`main.go` | 高 |
| 告警出口 | SOAR webhook / `EASM_ALERT_WEBHOOK` / SMTP | 未配置则仅落库/日志，不对外推送 | `notify/`；`main.go:239-258` | 高 |

**架构评价**：这些接缝是该项目最值得保留的部分之一。它们让“能力未启用”成为可观测的边界（501/如实标注），而不是伪造数据或静默降级。

---

## 9. 当前态 vs 目标态：不要混读

`docs/architecture/EASM-ARCH-OPT-v1.1.md` 是 **目标态/演进方案**，不是当前实现说明。两者关系：

| 主题 | 当前代码 | 目标态文档 v1.1 |
| --- | --- | --- |
| 使用形态 | 认证链、RBAC、`EASM_SINGLE_USER` 已存在；单用户安全补偿部分落地 | 单 operator + 重认证/双通道/冷却期/break-glass + 审计 |
| 数据域 | `/v1/entities` 别名；内部 tenant_id + 部分 RLS | `regulated_entities` + `entity_id` + RLS 数据域 |
| 业务主干 | 五阶段 + Finding/台账/工单/通报/报告 | 持续 EASM 运营环 + 辖区组合 + 周期评估 + 监管报送 |
| AI | Provider 接缝 + mm/shadowit/usage/evalset | 受约束 Agent 运行时 + “第二双眼睛” |
| 演进方法 | 已有 Phase 0/1/2/3 代码落点 | strangler + 兼容层 + 三门禁 |

**已落地的 Phase 1/2 能力（代码级）**：`inventory`（资产身份/观察流）、`finding`、`job`、`connector`、`discovery`、`detect`、`projection`、`alert`、资产衰减、Finding 批量操作。**仍在目标态文档中、但当前不应视为已完成**：辖区组合视图、周期评估、监管报送格式定稿、完整单用户双通道确认、真实暗网源、完整 WebAuthn/生产 IdP 联调。

---

## 10. 业务应用适配度（Agent 可安全改动的前置条件）

按 Business Application Fitness 的检查面：

| 检查面 | 当前状态 | 说明 |
| --- | --- | --- |
| 参与者与角色 | ✅ 明确 | operator/admin 与 R1–R8 权限矩阵在代码中 |
| 领域对象 | ✅ 明确 | Asset/Alias/Observation、Finding、Ledger Item、WorkOrder、Notice、Report、Job、Alert |
| 权限与数据域 | ⚠️ 部分 | RBAC + Scope + InScope 完整；RLS 仅 8 表；治理表靠服务层 |
| 生命周期 | ✅ 明确 | 四/五/十/五/七态状态机与转移表 |
| 端到端主路径 | ✅ 有代码与集成测试 | sweep/collect/ledger/verify/workorder/notice/report；live-smoke 55 项接线守卫 |
| 业务校验 | ⚠️ 部分 | 单测丰富；PG 集成测试需显式 DSN；仓库内未见 `.github/workflows`（见 §11） |
| 前端可操作性 | ⚠️ 演示 + 实时混合 | `console/app.js` 为演示数据；`easm-live.js` 水化真实数据；无前端构建/浏览器 E2E |
| 文档可导航性 | ✅ 强 | `AGENTS.md` 是单一仓库指南；编号追溯（FR/WP/IR/CR）机械校验 |

**结论**：领域模型、权限、状态机与主路径足以让编码智能体安全地做局部改动；主要风险不是“模型缺失”，而是 **双后端字段漂移、RLS 覆盖不均、文档/脚本口径漂移**。任何涉及 `ledger.Item` 字段、迁移列、store 实现的改动，必须同时跑真 PG 集成测试（`make test-integ`）。

---

## 11. 证据薄弱点、漂移与未知项

以下问题不是“架构缺陷宣判”，而是当前基线中**需要显式知道**的事实：

1. **CI 配置不在工作树**：`AGENTS.md` 描述 `.github/workflows/ci.yml` 四门禁，但基线目录中不存在 `.github/`。因此“CI 是否在远端强制执行”在仓库内**无法验证**（本地 `make vet/test/trace/openapi` 可跑）。置信度：高（目录不存在）/未知（远端状态）。
2. **端口口径漂移**：`config.Load` 默认端口已是 `8087`（`config/config.go:123`），而大量 live 脚本硬编码 `http://localhost:18080`（`scripts/*.sh`、`live-smoke.py`）。这是运行约定而非架构缺陷；启动脚本前必须先对齐端口，否则“端点不存在”的假象会误导排查。置信度：高。
3. **RLS 覆盖是部分的**：只有 8 张表启用 RLS；`ledger/workorder/notice/report` 等治理表没有数据库级 RLS，依赖租户范围查询 + `InScope`。若未来新增直接 SQL 入口，必须复用同一租户过滤，不能假设“有 RLS 兜底”。置信度：高。
4. **Neo4j Provider 未装配**：`graph.Neo4jHTTP` 代码存在，但装配根未挂载；当前图查询走内存 BFS 或 PG 递归 CTE。不要从文件存在推断“生产使用 Neo4j”。置信度：高。
5. **向量库/真实暗网源缺失**：MCP `knowledge_export` 如实返回 `vector_store=not_configured`；暗网为 fixture。均为外部项，不应在架构图中画成已运行能力。置信度：高。
6. **单用户安全补偿的完整度**：代码已有 confirmations、OIDC、break-glass、passkey step-up；但目标态要求的“双通道确认/冷却期/完整 WebAuthn/生产 IdP 联调”在仓库内无法全部证实。按“部分落地”理解。置信度：中。
7. **内存模式与 PG 模式行为差异**：内存 store 用于单测/演示，PG store 才是生产事实源；`ledger` 显式列同步问题是历史实测缺陷。任何“本地测试通过”都不能替代 `make test-integ`。置信度：高。
8. **静态控制台的“双重数据源”**：`app.js` 演示数据与 `easm-live.js` 实时水化共存；视图 h2 徽标默认“示例”，水化成功才升级“实时”。评估 UI 时必须区分真实/示例，不能把演示数字当生产数据。置信度：高。
9. **文档中的 Phase 进展是自述**：`EASM-ARCH-OPT-v1.1.md` 的“Phase 1/2/3 已落地”与代码大体吻合（inventory/finding/job/connector/detect/projection/alert 均在），但具体端点数量、外部项状态以其文档为准，未逐项复核。置信度：中。
10. **目标态文档与当前实现的口径差**：`tenant` 与 `entity` 双术语并存；阅读 API/DB 时把 `tenant_id` 当 `entity_id`，阅读目标态文档时按 `entity_id` 理解。置信度：高（代码注释已明示）。

---

## 12. 建议的阅读与验证顺序

1. 先读本文件 §0–§6，建立“进程 → 域 → 状态机 → 三重门”的心智模型；
2. 打开 `system-context.structurizr.dsl`（C4 上下文/容器）；
3. 打开 `module-map.dot`（模块依赖，先看 cluster，再看跨 cluster 的主干边）；
4. 打开 `flow-closed-loop.dot`（业务闭环，重点看门1/门2/门3 与工单/通报前置）；
5. 需要核对任一结论时，查 `system-model.evidence.md` 的 sourceRefs；
6. 需要验证当前基线可构建性时，按 `README.md` 的命令执行（`make build/test/vet/trace`；PG 集成需 `EASM_PG_DSN`）。

---

## 附录：本报告未覆盖的内容

- 具体 API 请求/响应字段级契约（以 `docs/api/openapi.json` 与 handler 为准）；
- 迁移逐表 DDL 与索引设计评审；
- 性能/容量（除仓库已有压测脚本外，未做实测）；
- 安全渗透测试与依赖漏洞扫描（未在本轮执行）；
- 目标态迁移的详细任务拆分（见 `EASM-ARCH-OPT-v1.1.md` 与详细开发计划）。
