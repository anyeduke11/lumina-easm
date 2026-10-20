# 当前态架构证据索引

> 基线：`v0.0.2`（2026-10-20）。
> 用途：为 `architecture-understanding.md`、`system-context.structurizr.dsl`、`module-map.dot`、`flow-closed-loop.dot` 中的结论提供可追溯出处。
> 置信度口径：**高** = 代码/迁移/脚本直接可见；**中** = 多处间接证据或文档自述；**低** = 仅有文档承诺；**未知** = 仓库内无法验证。

---

## A. 系统形态与构建

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-01 | Go 1.24.0 单模块，模块路径为 `github.com/wangdev88/easm-platform` | `go.mod:1-3` | 高 |
| EV-02 | 外部依赖仅 `lib/pq`、`minio-go/v7`、Temporal SDK；HTTP 使用标准库 | `go.mod:5-13` | 高 |
| EV-03 | 48 个 `internal` 包 + 6 个 `cmd` 包，合计 54 包 | `ls platform/services/internal`；`ls platform/services/cmd`；`AGENTS.md` 的 `make trace` 54 包口径 | 高 |
| EV-04 | 29 个迁移文件、34 张表 | `ls migrations | wc -l` = 29；`grep -rh "CREATE TABLE" migrations/ | wc -l` = 34 | 高 |
| EV-05 | 六个进程/入口：server、jobworker、worker、migrate、passkey、breakglass | `platform/services/cmd/*` | 高 |
| EV-06 | server 默认监听端口为 `8087` | `platform/services/internal/config/config.go:123` | 高 |
| EV-07 | live 脚本硬编码 `http://localhost:18080` | `scripts/authz-sop-drill.sh:5-7`；`scripts/crash-drill.sh:5-9`；`scripts/darkweb-demo.sh:2-4`；`scripts/kb-smoke.sh:2` | 高 |
| EV-08 | 仓库工作树中不存在 `.github/`，无法验证远端 CI 是否执行 | `ls .github` → 不存在；对照 `AGENTS.md` 的 CI 描述 | 高（本地不存在）/未知（远端） |

## B. 运行时容器与装配

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-09 | 装配根在 `cmd/server/main.go`，无 DI 框架 | `platform/services/cmd/server/main.go:61-545` | 高 |
| EV-10 | `config.Load()` 在启动最前执行，失败即 fatal | `main.go:62`；`config/config.go:101-181` | 高 |
| EV-11 | PG 分支：DSN 设置才打开 `pgstore`，否则内存模式 | `main.go:86-107` | 高 |
| EV-12 | 证据后端：`EASM_EVIDENCE` 仅允许 `file|minio`，非法即 fatal | `main.go:273-294` | 高 |
| EV-13 | 复测 Provider：HTTP 沙箱（`EASM_SANDBOX_URL`）或本机命令（`EASM_VERIFY_CMD`） | `main.go:296-312`；`verifier/` | 高 |
| EV-14 | AI 三件套同设才装配，缺失/半设=fatal，全未设=501 | `main.go:400-423`；`config/config.go` | 高 |
| EV-15 | `app.Deps` 汇总 30+ 域服务，`Handler()` 组装 REST、MCP、console | `platform/services/internal/app/deps.go:51-102,105-171` | 高 |
| EV-16 | `/mcp`、`/v1/*` 与 `/healthz` 走 API；其余走 console 静态面 | `app/deps.go:160-171` | 高 |
| EV-17 | jobworker 要求 PG；消费 Job 队列并执行资产衰减 | `platform/services/cmd/jobworker/main.go` | 高 |
| EV-18 | worker 要求 PG；Temporal activity 调用 `sweep.ExecuteInto` | `platform/services/cmd/worker/main.go` | 高 |
| EV-19 | 未配置 Temporal 时排查在进程内同步执行 | `main.go:195-205`；`httpapi.SweepDispatcher` 回退 | 高 |

## C. HTTP、MCP 与鉴权

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-20 | REST 路由集中注册，共 118 处 `mux.Handle` | `platform/services/internal/httpapi/server.go:226-356`；`grep -c "mux.Handle"` = 118 | 高 |
| EV-21 | `/v1/entities` 被重写为 `/v1/tenants`，作为一等别名 | `httpapi/server.go:358-374` | 高 |
| EV-22 | 认证链：dev token → OIDC → break-glass；全不中 401 | `httpapi/server.go:378-401` | 高 |
| EV-23 | 生产环境禁用 dev 静态令牌，必须 OIDC | `config/config.go:235-238` | 高 |
| EV-24 | 单用户模式要求恰好一枚 dev token（admin）或 OIDC | `main.go:534-540`；`config/config.go:126` | 高 |
| EV-25 | MCP 工具三级：readonly / controlled / dangerous | `mcp/server.go:38-40` | 高 |
| EV-26 | MCP 提供 16 个工具，包含 `scan_active`（dangerous）与 `knowledge_export`（readonly） | `mcp/server.go:150-260,476,524`；`grep -o 'Name: "[a-z_]*"' | sort -u` = 16 | 高 |
| EV-27 | MCP 工具调用与 REST 同闸，allow/deny 写审计 | `mcp/server.go` 调用分支与审计逻辑 | 高 |

## D. 领域状态机与治理

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-28 | 台账四态：open / doing / closed / notify | `ledger/ledger.go:20-23` | 高 |
| EV-29 | 台账 `closed` 不能直接设置，必须经 `Verify` | `ledger/ledger.go:376-404,413-456` | 高 |
| EV-30 | 门1：严重级须 ≥2 独立信源，否则降“高”并审计 | `ledger/ledger.go:254-283` | 高 |
| EV-31 | 门2：严重级须已回答反证；无回答降“高”，反证成立降“中” | `ledger/ledger.go:285-299` | 高 |
| EV-32 | `Verification.Validate` 要求 reproduced + evidence_ref | `ledger/ledger.go:91-116` | 高 |
| EV-33 | 工单五态与唯一跟催回退边；终态锁定 | `workorder/workorder.go:33-39`；`Advance` 在 `:194` | 高 |
| EV-34 | 工单建单必须挂同租户真实台账条目 | `workorder/workorder.go` 建单校验；`notice` 同类校验 | 高 |
| EV-35 | 通报 `Create` 校验台账存在且同租户，材料哈希 + WORM 固化 | `notice/notice.go:171-221` | 高 |
| EV-36 | 通报回执必填，首份回执锁定不可覆盖 | `notice/notice.go:225-254` | 高 |
| EV-37 | 通报交付包 `Chain` 可逐项复核 | `notice/notice.go:400` | 高 |
| EV-38 | Finding 十态生命周期；confirmed/closed 必须有证据 | `finding/finding.go:28-40`；`finding/` | 高 |
| EV-39 | 资产五态与 retired 必须给 reason | `inventory/inventory.go:29-33,251-270` | 高 |
| EV-40 | Job 七态；租约/幂等/退避/死信 | `job/job.go:29-34`；`pgstore` JobStore | 高 |
| EV-41 | 告警 open/ack/closed，幂等 `ALT-<sha12>` | `alert/` | 高 |
| EV-42 | 排查任务单 pending/done，done 终态，完成人必填 | `monitor/task.go` | 高 |
| EV-43 | 证据 WORM 接口：Put/Get/RefOf/Kind；租户路径校验 | `evidence/evidence.go:31-43` | 高 |
| EV-44 | 报告导出 MD/JSON/PDF | `httpapi/report.go:73-78` | 高 |

## E. 数据域、权限与审计

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-45 | RBAC 角色矩阵：admin/R1–R8 | `rbac/rbac.go:31-39` | 高 |
| EV-46 | `Principal.InScope(tenantID)` 做数据域过滤 | `rbac/rbac.go:52` | 高 |
| EV-47 | 授权单 Scope 字段：域名/CIDR/端口/排除/有效期/限速/时间窗/二次授权/签署人/文档哈希 | `authz/authz.go:26-41` | 高 |
| EV-48 | RLS 仅在 8 张表启用：assets、findings、finding_validations、inventory_assets、inventory_aliases、inventory_observations、jobs、alerts | `migrations/001_init.sql`、`025_inventory.sql`、`026_findings.sql`、`027_jobs.sql`、`029_alerts.sql`（`ENABLE ROW LEVEL SECURITY`） | 高 |
| EV-49 | PG 事务内设置 `easm.tenant_id` GUC | `pgstore/pgstore.go:39-55` | 高 |
| EV-50 | 应用角色 `easm_app` 无 BYPASSRLS | `migrations/002_role_app.sql`；`AGENTS.md` | 高 |
| EV-51 | 高危动作确认默认开启（`EASM_REQUIRE_CONFIRMATION=0` 才关闭）+ `X-EASM-Confirmation`；MCP `scan_active` 同闸 | `httpapi/confirm.go`；`mcp/server.go`；`config/config.go` | 高 |
| EV-52 | 审计 allow/deny 全量仅追加 | `audit/`；MCP/HTTP handler 调用点 | 高 |
| EV-53 | `ledger` PG 实现为显式列；新增字段须同步迁移/Create/Update/scan | `pgstore/ledger.go:20-22`；`ledgerCols` 在 `:22` | 高 |

## F. 发现链路与 Provider 接缝

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-54 | 五阶段 P1–P5 及步骤数 4/4/5/3/4 | `sweep/sweep.go:53-126` | 高 |
| EV-55 | 排查执行前校验授权 Scope；限速 per-run 累计 | `sweep/sweep.go:441-490` | 高 |
| EV-56 | collect 以 `exec.CommandContext` 执行 CLI 子进程 | `collect/collect.go:51` | 高 |
| EV-57 | 平台零扫描实现，工具经 plugin 契约注册 | `plugin/plugin.go`；`AGENTS.md` AX-6 | 高 |
| EV-58 | 暗网当前为 fixture；真实 feed 属外部项 G8-03 | `darkweb/darkweb.go:2,42` | 高 |
| EV-59 | 图 13 类实体、11 类关系 | `graph/graph.go:18-57` | 高 |
| EV-60 | `graph.Neo4jHTTP` 存在，但装配根未挂载 | `graph/neo4jhttp.go`；`cmd/server/main.go` 无 Neo4j 装配 | 高（未装配） |
| EV-61 | MCP `knowledge_export` 如实返回 `vector_store=not_configured` | `mcp/server.go:219,476` | 高 |
| EV-62 | Connector：seed/ct/dns/asm/cloud；未配置不注册 | `connector/`；`cmd/server/main.go` 装配 | 高 |
| EV-63 | 告警出口：SOAR/Webhook/SMTP；未配置不推送 | `notify/`；`main.go:239-258` | 高 |

## G. 前端与验证基线

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-64 | 控制台为纯静态单页；`app.js` 演示数据，`easm-live.js` 实时水化 | `console/index.html`；`console/app.js`；`console/easm-live.js` | 高 |
| EV-65 | live 层默认 Bearer `tok-admin`，统一走 `/v1/*` | `console/easm-live.js` | 高 |
| EV-66 | live-smoke 对 55 项 entity/tenant 端点做路由/接线双向守卫 | `scripts/live-smoke.py`；`AGENTS.md` | 高（脚本存在） |
| EV-67 | 单测默认零外部依赖；PG 集成测试需显式 `EASM_PG_DSN` | `*_integration_test.go` 的 skip 守卫；`Makefile` 的 `test-integ` | 高 |
| EV-68 | 仓库指南 `AGENTS.md` 是单一来源，包含编号/公理/命令/约定 | `AGENTS.md` | 高 |

## H. 文档自述与不确定项（不作为当前态事实）

| ID | 结论 | 证据 | 置信度 |
| --- | --- | --- | --- |
| EV-69 | 目标态为“监管单位单用户 + 被监管单位数据域” | `docs/architecture/EASM-ARCH-OPT-v1.1.md` | 中（目标态，非当前态） |
| EV-70 | 单用户安全补偿的完整形态（双通道/冷却期/完整 WebAuthn/生产 IdP 联调）尚属待办 | 同上文档的 Phase 0 进展与“仍待”列表 | 中/低 |
| EV-71 | Phase 1/2/3 进展为文档自述 | 同上文档；与代码能力大体对应，未逐端点复核 | 中 |
| EV-72 | 外部签字项（G8-02/03/04/05/06）不得代签 | `AGENTS.md` | 高（流程约束） |
| EV-73 | CI 四门禁的配置未在工作树中 | 对照 `AGENTS.md` 与 `ls .github` 结果 | 高（缺失）/未知（远端） |

---

## 图源到证据的映射（抽样）

| 图元素 | 支撑证据 |
| --- | --- |
| C4 容器 `REST API` / `MCP 服务` | EV-15、EV-16、EV-20、EV-26 |
| C4 容器 `Job Worker` / `Temporal Worker` | EV-17、EV-18、EV-19 |
| C4 外部 `公安 / 通报中心` / `第三方平台` | EV-33、EV-35、EV-36 |
| module-map 边 `sweep → ledger` | EV-54、EV-55、EV-30、EV-31 |
| module-map 边 `notice → evidence` | EV-35、EV-43 |
| module-map 虚线 `graph → Neo4j` | EV-60 |
| module-map 虚线 `mcp → 向量库` | EV-61 |
| flow 门1/门2/门3 | EV-30、EV-31、EV-32 |
| flow 工单/通报前置 | EV-33、EV-34、EV-35 |
| flow “AI 不裁决” | AX-2（`AGENTS.md`）；`ai/`、`mm/` 的装配边界 |

---

## 复算命令

```bash
# 包与 import 矩阵
go list -f '{{.ImportPath}}|{{join .Imports ","}}' ./platform/services/internal/...

# 迁移与表数量
ls migrations | wc -l
grep -rh "CREATE TABLE" migrations/ | wc -l

# RLS 覆盖
grep -rn "ENABLE ROW LEVEL SECURITY" migrations/

# MCP 工具清单
grep -o 'Name: "[a-z_]*"' platform/services/internal/mcp/server.go | sort -u

# 路由注册数量
grep -c "mux.Handle" platform/services/internal/httpapi/server.go
```
