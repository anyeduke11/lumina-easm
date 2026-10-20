# AGENTS.md — Lumina · 烛隐 EASM 仓库指南（面向 OpenCode 等编码智能体）

> **本文件是仓库指南的唯一来源**（2026-10-19 由 `CODEBUDDY.md` 合并而来并删除原文件：结构/约定取「改代码前必须知道的事」形态，路线图段保留完整历史演进记录 §16.1–16.15）。
> 权威上位文档在仓库外：`../EASM-AI-Native-Platform/`（总体设计方案 / PRD / SRS / 详细开发计划 / GAP-8 / M0-M1 收尾核查表 / **M4 收官过检表**）。**改动代码前先查其中的编号依据。**
>
> **2026-10-19 架构方向**：平台收敛为「监管单位单用户 + 被监管单位数据域」；Phase 0 已恢复绿色（`go build`/`go test` 通过），单用户化仍在推进。目标架构、单用户安全补偿与收口清单见 `docs/architecture/EASM-ARCH-OPT-v1.1.md`；本文件以下多租户/RLS 描述在后续同步前按「历史口径」阅读。

## 项目概览

Lumina「烛隐 EASM」——互联网敏感信息过度泄露排查 / 外部攻击面管理平台。Go 1.24 单模块（`github.com/wangdev88/easm-platform`），依赖极少（`lib/pq`、`minio-go/v7`、Temporal SDK），HTTP 层直接用标准库 `net/http`（Go 1.22 `ServeMux`），无 Web 框架。业务代码全部在 `platform/services/internal/` 按域分包。

**当前版本：v0.0.2**（公开仓库 `anyeduke11/lumina-easm`，README/CHANGELOG 随代码入库）。版本号与发布说明维护在 `CHANGELOG.md`；涉及对外能力变更时同步更新 README「v0.0.2 边界」一节。仓库模块路径 `github.com/wangdev88/easm-platform` 为历史既定值，未随公开仓库改名——改动前不要擅自替换。

上位依据是《互联网敏感信息泄露排查》工作文件：监管五阶段（P1 搜索引擎 / P2 空间测绘 / P3 端口目录 / P4 第三方渠道 / P5 暗网）、三类敏感数据（34 项 / 22 条规则）、整改工作建议。

## 常用命令

```bash
make build / test / vet / lint / trace  # go build|test ./... | go vet | golangci-lint | C-1 追溯对账
make test-integ                       # 集成测试：EASM_PG_DSN=easm_app 角色跑全量 ./...
make migrate / migrate-status / migrate-baseline  # cmd/migrate + schema_migrations；baseline 仅用于既有库首次接入
make openapi                          # 生成 docs/api/openapi.json 并校验路由/entity 别名覆盖
make run-local                        # 本地 PG 模式起 server（默认 :8087）
make run                              # 纯内存模式起 server（dev 令牌演示）
make start / stop / restart / status / logs  # 单服务管理（编译产物+PID 收敛；env 覆盖 scripts/easm.env，模板见 easm.env.example）
make start-all / stop-all / status-all  # 全系统一键：PG→迁移→server→jobworker→（EASM_TEMPORAL_HOST 已设时）Temporal+worker
make run-worker / temporal-dev        # Temporal worker / 本机 dev server（:7233）
make run-jobworker                    # Phase 1/2 发现 Job Worker（PG 队列；可多实例）
make verify                           # 收口套件：test-integ + kb-smoke + live-smoke + authz-sop-drill
make backup                           # pg_dump 快照
```

单测：`go test ./platform/services/internal/sweep/ -run TestService -v`。
集成测试：`EASM_PG_DSN=postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable go test ./platform/services/internal/pgstore/ -count=1`。

端到端脚本：**server 必须监听 `:18080`**（`PORT=18080`，与默认 8087 不一致是常见坑），默认 Bearer `tok-admin`：`kb-smoke.sh`（知识库）、`live-smoke.py`（前端接线回归 55 项 entity/tenant 级端点双向守卫）、`authz-sop-drill.sh`（授权 SOP 预演）、`workorder-live.sh` / `notice-live.sh` / `darkweb-demo.sh` / `darkweb-persist-drill.sh` / `notice-chain-live.sh`（M2 各域 live）、`crash-drill.sh`（Temporal 断点续跑）、`g806-bench.py`（压测）、`g804-license-check.py`（许可证取证）、`verify-local-demo.sh`（门3 简单隔离复测契约样例，配 `EASM_VERIFY_CMD` 装配）。

注意：`make run` 是纯内存模式，`make start`（service.sh）默认 PG 模式（`scripts/easm.env` 可覆盖）——两者数据面不同，排查「数据不见」先确认起的是哪个。

## 编号体系与口径

- 追溯链（C-1 编号闭合）：PRD 功能点 F1–F18 → SRS 的 FR/DR/IR/NFR/CR。包注释与提交信息携带 FR/WP/IR 编号，新增实现须回写追溯，不留孤儿需求。`make trace`（scripts/trace-check.py）机械对账：每个 Go 包注释须携带编号（当前 54 包全过）。
- 口径唯一：五阶段 P1–P5 步骤数 **4/4/5/3/4**；子能力码 STR-1~5 / MAP-1~4 / SCAN-1~5 / EXT-1~3 / DRK-1~2；工具输出统一归一为 `easm.candidate.v1`（kind ∈ asset/finding/lead，解析失败进 `unsupported` 保留原文+原因）；风险四因子默认权重 30/30/25/15。
- **SRS §10 十一条一票否决**（任一条违反即不予发布，改动相关代码前必读）：五阶段覆盖不全；34 项/22 规则缺失；台账必填字段可绕过；跨租户串权；通报超时无标识无升级；扫描授权可绕过；内网不可用；首屏 >3s；严重级结论不可验证（AX-3）；插件破坏主干或平台含工具专有扫描实现（AX-6）；高危动作无人工确认（AX-5）。

## 架构

### 六条设计公理 → 代码约束

| 公理 | 在代码中的落点 |
| --- | --- |
| AX-1 数据是地基（图谱） | `internal/graph` + `ingest.Projector` 资产入账即投影；图谱是资产清单的母体 |
| AX-2 确定性发现 + AI 判断（辅助、不裁决） | 平台确定性规则/CLI 为事实源；判敏走 `internal/classify` 22 规则；`internal/ai` 为 Provider 接缝（M3-D/ENH-03，AI 结论不入台账） |
| AX-3 一切皆可验证 | 证据先行（C-5）：`evidence.Store` WORM，`raw_ref`/`snapshot_ref` 可回溯；ledger `closed` 必须经 `Verify`，未装配 verifier 返回 501（禁止造假闭环） |
| AX-4 持续闭环 | ledger 四态状态机；workorder 五态（待整改→处置中→已通报平台→已下架→已处置，跳步/终态出边全拒=不可虚报闭环） |
| AX-5 人在环可审计 | 四类高危动作（爆破/主动扫描/跨租户读取/对外通报）强制人工确认；audit allow/deny 全量仅追加落 PG；notice 三要素列锁定 + DB 触发器 |
| AX-6 一切皆插件 | 平台零扫描逻辑；工具经 `internal/plugin` 契约注册，CLI 子进程是唯一执行形态（本平台不对对外部署，容器化已移除） |

### 进程与装配

主要 `main`：`cmd/server`（REST `/v1/*` + MCP `/mcp` + console 静态面）、`cmd/worker`（Temporal activity worker）、`cmd/jobworker`（Phase 1/2 发现与判敏 Job Worker）；另有一次性的 `cmd/migrate` / `cmd/passkey` / `cmd/breakglass`。装配全部发生在 `cmd/server/main.go` 的 `main()`，无 DI 框架——顺序构造各 `Service` 后手工传给 `httpapi.New(...)` / `mcp.New(...)`。两条铁律不可破坏：

1. **env 设了但装载失败一律 `log.Fatalf`（fail loud），拒绝静默降级**：`EASM_PG_DSN`、`EASM_TEMPORAL_HOST`、`EASM_EVIDENCE`（仅 `file|minio`）、KB 接 PG、AI 三件套（缺失/半设=fatal）等。
2. **可选能力未装配时端点返回 501 + machine-readable code**（`collect_unavailable`、`graph_unavailable`、`verifier_unavailable` 等），不返回空数据；也不得伪造（如 `notice_persisted:false` 如实标注）。

### 双后端：内存 ↔ Postgres

`EASM_PG_DSN` 是否设置决定分叉：内存模式 = 各域 `NewMemStore()`（单测/演示用）；PG 模式 = `pgstore.Open(dsn)` 统一替换 store，并挂上仅 PG 侧能力（`Tenants`、`Assets`、`Ledgers`、`KB`、`Sweeps`、`Authz`、`WorkOrders`、`Notices`、`Reports`、`Audit`、`Graph`、`Snapshots`、`NotifyLog`、`Darkweb`、`OwnershipQueue`、`Candidates`、`MonitorTasks`、`Usage`、`Inventory`、`Findings`、`Jobs`、`Alerts`）。

因此**每域定义自己的 `Store` 接口 + 内存实现**，PG 实现集中在 `internal/pgstore/`（一个 `DB` 句柄派生各 store）。新域照此模式：接口在域包、实现在 `pgstore/<域>store.go`、装配写在 `main()`（内存 store 声明 + PG 分支赋值两行都要写）。**注意 `ledger` 的 PG 实现是显式列而非 JSONB——`Item` 新增字段必须同步「迁移列 + Create + Update + `scanLedger` 目标参数」四处：不加列=静默丢字段（内存正常的双后端漂移），漏 Scan=运行期 500。Plain `go test` 会 skip 集成测试从而掩盖，必须 `make test-integ` 验证（V-5/V-10 各实测一次）。**

RLS 语义（`pgstore.withTenant`）：事务内 `set_config('easm.tenant_id', ...)`；`ListByTenant` 设真实 tenant 行过滤，`Get` 设空串显式穿透、跨租户可读后由 Service 层 `InScope` 判 403 + deny 审计（内存/PG 契约一致，C-6）。**应用 DSN 必须是 `easm_app` 角色**（无 BYPASSRLS，`002_role_app.sql`），管理员 DSN 跑服务会让 RLS 静默失效。迁移由 `cmd/migrate` 按 `schema_migrations` 应用（`make migrate`；既有库首次接入用 `make migrate-baseline`），每个迁移自带 `GRANT ... TO easm_app`；schema 双份实现时注意同步。注意个别端点按设计返资源级 404（如 `ownership/fingerprints` 未登记基线不伪造空基线）——判「路由是否存在」要用 OPTIONS（405=在/404=不在），不能用 GET。

### HTTP 层

`internal/httpapi/server.go` 的 `Handler()` **集中注册全部路由**（其他文件只提供 handler），用 `Option` 函数选项（`WithLedger`、`WithDarkweb`…）注入能力，未注入即 nil → 501。路由用 Go 1.22 模式语法（`GET /v1/tenants/{id}/assets`，`r.PathValue` 取值）。

鉴权链：`auth()` 中间件从 `Authorization: Bearer` 查 `EASM_DEV_TOKENS` 静态表（`token:role:t1|t2`，`*`=全部）得到 `rbac.Principal` 注入 context；未命中时依次尝试 OIDC（`EASM_OIDC_*`，RS256/JWKS）与 break-glass（`EASM_BREAKGLASS_HASH`，每次使用写审计），全不中即 401。handler 内再显式 `p.Can(Perm...)` + `scopeAssets`/`InScope` 做 entity 过滤。**单用户模式**：`EASM_SINGLE_USER=1` 要求恰好一枚 dev 令牌或 OIDC（二选一，不可都空）；dev 令牌固定为 `admin` 角色，`R1..R8` 保留为历史/测试别名。**entity 路由**：`/v1/entities` 是 `/v1/tenants` 的一等别名（HTTP 层重写，内部仍用 tenant 表/RLS 作为 entity 数据域）。**组装根**：`internal/app.Deps.Handler()`（替代 28 参数 `newRouter`）；`internal/config` 集中装载/校验 env。顶层分流：`/mcp` → `mcp`（JSON-RPC 2.0；同一认证链、Scope 工具层强制）；`/v1/*`、`/healthz`、`/readyz` → api；其余 → `console/` 静态面。**可运维性**：`/readyz` 注入 `app.Deps.Ready`（PG 模式=`DB.Ping`，2s 超时；失败 503 `not_ready` 且不泄露内部地址；内存模式无外部依赖=ready）；`Handler()` 外层 `recoverPanic`（单请求 panic→500 `internal`+request_id，堆栈只入日志）；`cmd/server` 监听 SIGINT/SIGTERM，10s 优雅排水后关闭 PG 连接池。

### MCP 面（M4-04 全量开放）

`internal/mcp` 工具分级 = C-4 唯一权限口径：`readonly` 自动放行 / `controlled` 审计留痕 / `dangerous` 与 REST 同闸不特权（AX-5）。工具随装配动态出现（依赖未注入=工具不出现）：只读 `list_tenants`、`search_assets`、`get_asset`、`detect_sensitive_data`、`list_ledger`、`get_sweep_status`、`list_alerts`、`list_workorders`、`list_notices`、`list_reports`、`graph_top_paths`、`list_vulns`、`knowledge_export`；受控 `scan_schedule`（触发排查）、`report_generate`；高危 `scan_active`（主动扫描，须有效授权单；`EASM_REQUIRE_CONFIRMATION` 开启时与 REST 同闸，须 `confirmation_id` 参数或 `X-EASM-Confirmation` 头）。全部调用（allow/deny）写 audit 日志；新增工具须同步 `toolDefs()` 与 `tools/call` 分支、带 level 字段。

### Phase 1 EASM 核心（inventory / finding / job / connector / discovery）

- **资产身份/观察流**：`internal/inventory` 定义 `Asset` + `Alias` + `Observation`（append-only）；`Ingest` 复用 `graph.Fingerprint` 归一，按 canonical key/alias 合并，观察按 `entity+payload_hash` 幂等；`entity_id` 是数据域，PG 侧 `withTenant` + RLS。
- **发现 Connector**：`internal/connector` 定义 `Connector`/`Registry`；已实现 `seed`（手工种子）与 `ct`（crt.sh，测试可替换 BaseURL/HTTPClient）。新增 Connector 只实现接口并注册。
- **发现编排**：`internal/discovery` 把 `Connector` → `Observation` → `inventory.Ingest` → `graph.UpsertEntity/UpsertRelation`（`owns` 等）串起来；`Observation.Finding` 可携带 FindingHint，平台负责创建 Finding；`Worker` 消费 job。
- **Job Queue**：`internal/job` 状态 `queued/leased/running/succeeded/failed/dead/canceled`；PG `FOR UPDATE SKIP LOCKED` 租约、`idempotency_key` 去重、失败退避/死信；`cmd/jobworker` 独立消费。
- **Finding**：`internal/finding` 生命周期；`confirmed` 必须带 `evidence_ref`（C-5），`closed` 仅 confirmed/verified 且必须有证据；验证记录落 `finding_validations`。
- **迁移**：`025_inventory.sql` / `026_findings.sql` / `027_jobs.sql`；OpenAPI 已覆盖新增端点。

### Phase 2 检测与运营闭环

- **DNS/ASM Connector**：`connector.NewDNS()`（A/AAAA/CNAME，`resolves_from`/`cname_of` 写入 `resolves_to` 边）；`connector.NewASM(base, token)` 通用 ASM feed 适配器（`EASM_ASM_URL`/`EASM_ASM_TOKEN`，未配置则不注册）。
- **Finding 自动生成**：`internal/detect` 复用 `classify` 22 规则，观察值+payload 命中即创建 Finding；Finding ID 确定性，重复观察幂等；high/critical 自动 raise 告警。
- **Finding→ledger 投影**：`internal/projection` 把 confirmed/verified Finding 投影为 `ledger.Item`（P4、代码密码类/系统架构类、7 天 due），严重级仍走 ledger 门1/门2；`POST /v1/entities/{id}/findings/{fid}/project` 幂等。
- **资产状态机**：`candidate → confirmed → active ↔ stale → retired`；retired 必须给 reason；`POST /v1/entities/{id}/inventory/{aid}/state`；迁移 `028`。
- **告警**：`internal/alert`（open/ack/closed，幂等 ALT-<sha12>）；`GET /v1/entities/{id}/alerts`、`POST .../alerts/{aid}/ack`；迁移 `029`。
- **前端资产/发现视图**：`view-assets` 增加身份资产、Finding、Job、告警四张实时表；`easm-live.js` 按 `EASM.data.state.tenant` hydrate，失败按表标注。

### Phase 3 运营与治理增强

- **告警通知通道**：`alert.Service.WithNotifier(notify.Service)`；`POST /v1/entities/{id}/alerts:dispatch` 把 open 告警映射为 `monitor.Alert` 后走既有 notify 三闸门（高危过滤/通道去重/失败上浮）。
- **Finding 批量运营**：`POST /v1/entities/{id}/findings:bulk`，action=`confirm|close|project`，逐条返回失败原因；project 仍受 confirmed/verified 与台账门1/门2 约束。
- **资产自动衰减**：jobworker 每 `-decay-every`（默认 10m）扫描；`EASM_ASSET_STALE_AFTER=720h` / `EASM_ASSET_RETIRE_AFTER=2160h`；`POST /v1/entities/{id}/inventory:decay` 可手工触发；retired 终态。
- **Cloud Connector**：`connector.NewCloud` 复用通用 feed 契约（`EASM_CLOUD_URL`/`EASM_CLOUD_TOKEN`），未配置不注册。
- **前端**：运营表关键字筛选 + 分页；Finding 行内投影台账；告警通道选择与推送；报告中心入口。

### 五阶段工作流与治理闭环

核心链路：`POST /v1/sweeps` → `sweep.Service` 按 P1–P5 逐资产检测（台账反推去重集，账本=唯一事实源）→ 命中写 `ledger`（`L-<年>-<序号>`；外部采集 `L-EXT-<sha12>`、扫描 `L-SCAN-*`、暗网 `L-DRK-*`）。`collect`（scan:repo/:port/:dir，gitleaks/nmap/ffuf 子进程）与 `darkweb`（线索包 `LPK-*`）是并行采集入口；`ingest.Projector` 把入账资产投影为图谱实体。

**授权闸是一票否决⑥**：`sweepSvc.SetScope(authzSvc)` + `collect`/`darkweb` 各自 `authz.Validate`（有效期/时间窗/排除项/端口收窄/二次授权），主动渠道另有 `CheckTarget` 细目标闸与 `rate_limit`→工具参数（nmap `--max-rate`/ffuf `-rate`）消费。**编排层限速接缝（S-1 销账）**：`sweep.Service.WithLimiter(authzSvc)`——每次执行读一次 scope，执行行回显 `rate_limit` 并在资产判定轮间施加令牌桶步间最小间隔，等待毫秒 per-run 累计写 `paced_ms`（**必须 per-run 归属，不得放 Service 级字段**：跨 sweep 累计=别行的等待写进本行=取证失真，曾实测暴露并以 `TestSweepPacedMSIsPerRun` 虚拟时钟守卫锁定）；两字段随执行行落 PG（`030_sweeps_pacing.sql`，`sweepCols`/`Save`/`scanSweep` 三处同步——新增 `sweep.Sweep` 字段同样须三处加列，否则双后端静默漂移）。

**零误报三重门**（门1/门2 在 `ledger.Create` 统一执行，所有入账路径共用，旁路无门；门3 在 `Verify`）：

- 门1（V-5）：`Level=严重` 须有 ≥2 个独立信源（`Item.XChk`），否则降「高」+ 留痕 + `ledger.gate1_downgrade` 审计；
- 门2（V-10）：`严重` 须有已回答的反证（`Item.Refute`：claim/outcome/evidence），无回答降「高」、反证成立（confirmed）降「中」，均留痕 + `ledger.gate2_downgrade` 审计；
- 门3（S-2）：闭环必须经 `POST /v1/ledger/{id}/verify`——`Verification`（method/result/verifier/evidence_ref）写入 `Item.Verifs`（`018` jsonb 列）；`reproduced` 必带 `evidence_ref`（C-5）→closed，refuted/inconclusive→doing；manual/cross_tool=人在环可用，**sandbox 走 `Verifier` provider 端口，两种 Provider（接缝不变、替换装配）**：① `EASM_SANDBOX_URL`→`verifier.Sandbox`（HTTP 前端 provider，回执硬闸=result 枚举+reproduced 必带 evidence_ref，非 200/回执残缺一律上浮；ENH-10 微 VM 池本体=外部环境项）；② `EASM_VERIFY_CMD`→`verifier.Local`（**简单隔离**=ulimit 文件写空间+nice 压低优先级+超时+一次性工作区，产物 tar 入 evidence WORM；复测契约=`<cmd> <item_id> <tenant> <workdir>`，工作区写 `result.txt` 为唯一裁决出口，样例 `scripts/verify-local-demo.sh`）；两者互斥（HTTP 优先）；都未设→501 `verifier_unavailable` 禁止冒充闭环。

信源/反证由 sweep（资产在用状态）、collect（示例夹具路径 / HTTP 有效性）、REST（`xchk`/`refute` 字段）供给。

**ledger 是下游读口闸**：`workorder`（五态 + 必挂同租户真实台账条目，`WO-<sha12>`）、`notice`（线索通报 `NB-<sha12>`，公安 24h/通报中心 48h，A-08 超时催办，回执锁定，`/notices/{nid}/chain` 交付包逐项 sha256 可独立复核）、`report` 都以台账条目存在且同租户为前置。闭环只认真实复测，`verify` 未装配即 501。

外部依赖经 env 切换且接缝稳定：`evidence.Store`（`file`/`minio`）、`notify`（SOAR webhook / `EASM_ALERT_WEBHOOK` / SMTP，统一出口三闸门：只推高危/去重/失败上浮）、`httpapi.SweepDispatcher`（Temporal 或进程内回退）。

### Temporal 与后台

设 `EASM_TEMPORAL_HOST` 即装载 `tdispatcher`（TaskQueue `easm-sweep`，Workflow `SweepWorkflow`），否则进程内同步执行；server 与 worker **必须共享同一 `EASM_PG_DSN`**（worker 侧为空直接 fatal）。activity 用顶层函数注册并返回 string（SDK v1.42 结构体活动/void 返回有已知坑，见 `cmd/worker/main.go` 注释）。诊断开关 `EASM_WORKER_ECHO=1`、`EASM_ACTIVITY_CRASHAT=N`。`monitor.Service.Start()` 起进程内定时 loop（R7 全量主体取数、请求级仍按主体过滤），diff 基线存 `Snapshots()`；`monitor/task.go` 排查任务单（RT-<sha12>，同源 pending 收敛不堆叠、done 终态 409、完成人必填，迁移 `021`）。

### 前端

`console/` 纯静态单页：`app.js` 是演示数据与视图渲染（不发起真实请求），`easm-live.js` 是真实数据水化层（IIFE 注入令牌条，`api()` 统一加 Bearer，默认 `tok-admin`；已切 `/v1/entities`）。`live-smoke.py` 守护接线：`easm-live.js` 引用的每个 `/v1/` 路径必须在路由表存在，并对 55 项 entity/tenant 级端点做双向守卫（路由存在 + JS 引用；OPTIONS 405/404 判别），同时断言 M2/S-3 导航徽标挂载点（`navWoCount`/`navNoticeCount`/`navPkgCount`/`navRptCount`）与接线函数（`setPill`/`easmJumpTo`）——徽标实时计数（null=隐藏=无数据不留 0 噪音），视图内跳转按钮共用 `easmJumpTo`。视图 h2 静态徽标默认「示例」，live 层 hydrate 成功升级为「实时」（`markLive`）——未接视图保持「示例」，页内可区分真实/示例。合规报送卡片的按钮必须派发到真实路径（`easmComplianceAct`），禁止 toast 虚构「已生成/已审批」。

### AI 与计量（ENH-03 / M4-07）

- `internal/ai`：Provider 端口（SenseNova 首个装配，OpenAI 兼容），`EASM_AI_BASE_URL`/`EASM_AI_MODEL`/`EASM_AI_API_KEY` **三件套同设才装配，缺失=fatal、全未设=501**；空回执 fail loud；密钥只走 env 不落代码。消费面：`internal/mm` 多模态判敏（`POST /v1/tenants/{id}/mm:analyze`，VLM 判敏→约定 JSON→解析失败=unverifiable 不入图；资产在图内→`mm_*` 可解释 props 非破坏富化；AI 结论不入台账）、shadow:advise `with_ai=true` 文案层（判定/动作集不变）。
- `internal/usage`：AI 面按租户 token 计量（`ai.ChatResponse.Usage` 透出 + `mm.SetUsage`/`shadowit.WithUsage` 挂点；迁移 `022`），端点 `GET usage/summary`（byFeature/byModel）、`POST usage/budget`；达到/超出即告、当月一次、未设预算=如实标注、**超预算不阻断调用**（硬闸=evalset 放量门禁）。
- `internal/evalset`：评测集与反馈门禁（样本/指标 F1·κ·误报率·幻觉率/放量门禁 `EASM_EVAL_THRESHOLDS` 非法即拒、无记录 fail closed / 台账回流），灰度放量 `evalset/promote` 落 `EP-<sha12>` 留痕；未放行 403 `eval_gate_blocked`。

## 路线图与增强项（ENH）登记

M0 基座、M1 排查治理已收尾（D1 签认「内部验证形态 MVP 达成」）。**M2 确定性范围全部交付并收口**：M2-01 collect 三渠道、M2-02 暗网兜底（真实 feed 待 G8-03）、M2-03 工单、M2-04 通报与证据链、M2-09 报告中心（导出 md/json/**pdf** 三格式——PDF 为零依赖确定性 writer + **字体子集化**（glyf/loca 重建+复合组件 GID 重映射，29MB→126KB），字体缺失=501 诚实边界）、FR-CHN-007 线索包导出面均已交付；审查后修订轮 V-1~V-10 完成；**S 批完成（S-1 rate_limit 销账、S-2 门3 前置=018、S-3 四视图接线、S-4 沙箱接缝、S-5 简单隔离=`EASM_VERIFY_CMD`；BUG-06/07 入册）**。**M2 剩余全部为外部项**：M2-05~08/10 阻塞于 ENH-10（外部环境+签字；装载缝 `EASM_SANDBOX_URL` 就绪=零代码改动）、G8-02 定稿后通报格式细调（挂接点=`RenderPackageMD`+notice chain 渲染，单点）、G8/K 系列签字（不代签）。**M3 确定性范围（A/B/C/E）收口 + ENH-03 AI 面已交付**：WP-M3-02 三重门已被 M2 提前交付（仅剩 ENH-10 真实形态）；**M3-A**——`internal/scoring` 四因子评分确定性核（暴露可达 30/可利用性 30/资产重要性 25/凭据有效性 15，明细含依据、贡献和=总分可复算），端点 `GET /v1/tenants/{id}/assets/{aid}/score` 与 `GET /v1/tenants/{id}/scoring/weights`，权重/阈值经 **`EASM_SCORE_WEIGHTS`/`EASM_SCORE_THRESHOLDS`** 注入（非法装载即拒，默认标注「待 G8-01 定稿」=GAP-8 定稿后仅换配置）。**M3-B**——`graph.PathQuery` 端口 + 双实现（`MemPath` Go BFS / `pgstore.PGPath` 递归 CTE；**排序去重共用 `graph.RankPaths`**=切后端不换结论，集成测试同图对账真 PG 跑通），端点 `GET /v1/tenants/{id}/graph/{paths,reach,subgraph,top-paths}`（未装配=501 `graph_path_unavailable`），内存模式补齐 `graph.NewMemStore` 图谱后端（此前 501）；路径直出边序/跳数/目标种类/缓解建议（11 类关系全覆盖）/入选理由，默认深度 6、TopN 5；**登记缺口**：图谱边当前仅 `resolves_to`（资产投影），`leaks`/`valid_on` 等边无写入方→真实数据下 Top5 恒空（如实返空，M3-C 联动闭合）。**M3-C**——① `internal/secret` 密钥有效性三档（context 占位/示例路径 → format 已知形状+长度+字符集 → probe 非破坏 GET 外呼，`EASM_SECRET_PROBE=1` 显式开启，默认关闭；**外呼目标默认仅公网**——http(s) 方案 + 受限地址黑名单 + 拨号前对 DNS 解析结果校验（防 rebinding），内网目标须 `EASM_SECRET_PROBE_ALLOW_PRIVATE=1` 显式放开且须同时开探针，否则启动拒绝）+ 五状态（valid/revoked/invalid/unverifiable；**未外呼=unverifiable，不把「看起来像」当可用**）+ 度量端点（分母/分布/误报率/**口径**），端点 `POST /v1/tenants/{id}/secret:verify`、`GET /v1/tenants/{id}/secret/metrics`；**图谱边供给=仅 valid 凭据连 `leaks` 边**（闭合 M3-B 缺口：Top5 由 0 条→真实 1 跳）；密钥明文不入库不回显（仅脱敏+位置）；② `internal/shadowit` 影子 IT 收敛建议（复用 `ownership.Judge`）+ 纳管人审面，端点 `POST /v1/tenants/{id}/shadow:{advise}`、`POST /v1/tenants/{id}/shadow/admit`；**红线落代码**：建议无副作用、疑似动作集不含 admit、纳管双闸（判定归属+reviewer，疑似纳管 409 `not_owned`、缺人审人 400 `review_required`）。登记缺口：密钥自动投递通道（gitleaks `--redact` 不落密钥值）、JWT/私有形状判据、外呼 `rate_limit` 消费（`Pacer` 端口已预留）。**M3-E**——`internal/evalset` 评测集与反馈门禁骨架（WP-M3-06/FR-VRF-004/AIL-7）：样本（`Subject` 端口，现仅装配确定性判敏引擎 `classify-22rules`）+ 指标（F1/κ/误报率/幻觉率，全部由混淆矩阵复算）+ **放量门禁**（阈值 5 元组 `EASM_EVAL_THRESHOLDS` 注入非法即拒；无记录=fail closed；按当前口径重算、`run.gate` 仅运行时快照）+ **台账回流**（Refute confirmed/复测 refuted→误报样本、最近复测 reproduced→真阳性、refuted 信号优先、inconclusive/无信号跳过留痕；EV-<sha12> 幂等），端点 7 个（`evalset/{samples(GET,POST),relabel,reflux,runs,gate}`、`evalset:run`），迁移 `019_evalset.sql`；幻觉率口径=无证据阳性结论占比（AI 面预留，接缝不变）。**M3 收口核查完成（§16.9）**：机械验证全绿；G8-01/ENH-10 定稿=仅换配置/换 Provider，不代签。**ENH-03 AI 面已交付（§16.10）**——`internal/ai` Provider 端口（SenseNova 首个装配：OpenAI 兼容，三件套同设才装配、缺失=fatal、全未设=501；空回执 fail loud；密钥只走 env）+ 三消费面：① `internal/mm` 多模态判敏（约定 JSON→解析失败=unverifiable 不入图；`mm_*` 非破坏富化；AI 结论不入台账）；② shadow:advise `with_ai=true` 文案层 `ai_basis`（判定/动作集不变）；③ `evalset/promote` 灰度放量动作面（未放行 403 `eval_gate_blocked`；`EP-<sha12>` 留痕，迁移 `020`）。**M4 确定性范围全部交付（§16.11~16.15）**：**M4-03** 排查任务单（`monitor/task.go` RT-<sha12>；diff_new/diff_changed/new_poc 触发；同源 pending 收敛刷新不堆叠、done 终态 409、完成人必填=AX-5；`021`+`pgstore.MonitorTaskStore`+端点 3）；**M4-07** 计量与预算（`internal/usage`+`ai.ChatResponse.Usage`+`mm.SetUsage`/`shadowit.WithUsage`；`022`+`pgstore.UsageStore`+端点 2；达到/超出即告、当月一次、未设预算如实标注、超预算不阻断调用）；**M4-04** MCP 全量开放（`toolDef.level` C-4 分级、工具 16 个、受控/高危与 REST 同闸双层纵深、allow/deny 全量审计、`notify.SOAR` HMAC 通道、`knowledge_export` 如实返空）；**M4-06** 离线包结构（原 `deploy/helm` 骨架+`offline/MANIFEST.md`+`OPS.md`；**2026-10-19 平台定位收敛为内部单机形态，容器/K8s 部署路线整体移除，deploy/ 目录已删除**）；**M4-05** 收官过检（十一条一票否决机械面 11/11，M4-收官过检表 EASM-M4-CLOSE-v1.0）。**M4 状态：确定性范围全部交付**——M4-01/02（原 ENH-09 K8s 部署，**2026-10-19 随容器化路线整体取消**）、G8-02/03/04/05/06（签字）、ENH-02 向量库本体、ENH-07 OIDC、ENH-10 沙箱真实形态；M5 不立项（上位 WBS 仅覆盖 M0–M4）。

ENH-01~10 是取消/延后方案的正式 backlog（Temporal/Neo4j/向量/Redis/MinIO/ClickHouse/OIDC/Harness；**原容器/K8s 两项（ENH-08/09）随 2026-10-19 定位收敛已取消**）。**机制：接缝不变、Provider 替换**——启用某项 = 在既有接口挂新 Provider + 契约测试，上层零改动；未启用项在界面/文档显式标注能力边界，不静默降级。

本地化约束（开发计划 §14）：开发机无容器，**PG 是唯一必需外部依赖**；Temporal/MinIO 走 brew 非容器；`psql`/`pg_dump` 路径硬编码 `/opt/homebrew/opt/postgresql@18/bin/`。

## 开发约定

- **TDD 红→绿→变异验证**（项目固定纪律）：每个功能/修复先写失败测试，再实现，最后做变异验证（故意破坏实现确认测试能捕获），结果记入文档进展日志。缺陷修复须补提交级守卫断言（参考《缺陷回归用例集》与 `sweep` findings 双断言先例）。
- **fail loud 优于兜底**：装配失败、存储失败、授权缺失一律上浮或拒绝；禁止半可用状态（如「材料出了但查不到」）、禁止伪造数据冒充真实（合成单号、空基线伪装等先例均已按此修正）。
- **口径同步**：运行时消费缺口要如实登记再闭合（如 `time_window`/`rate_limit` 先登记缺口后消费）；文档与代码同批提交，「纯文档登记轮」是常规轮次。
- 测试约定：绝大多数 `*_test.go` 零外部依赖（`httptest.NewServer` + 内存 store），`go test ./...` 不要求 PG；PG 集成测试统一 `*_integration_test.go`，首行 `if os.Getenv("EASM_PG_DSN") == "" { t.Skip(...) }`，`t.Cleanup` 清 `itest-%` 残留；测试基建 `httpapi/server_test.go` 的 `newTestServer(t)`（双租户 + R7/R1/R5 三令牌），跨租户用例同时断言 403 与 deny 审计；表驱动断言错误哨兵值（`authz.ErrNotInScope` 等）；安全测试带「为什么」注释。
- CI（`.github/workflows/ci.yml`）四门禁：① `go vet`/`go build`/单测；② `cmd/migrate up` 空库迁移 + `easm_app` 角色 PG 集成；③ OpenAPI 生成/覆盖校验；④ `trace-check` + golangci-lint（blocking）。新增包必须在包注释携带 FR/WP/IR/CR/ENH 编号。
- 插件合规护栏：传染性许可证（AGPL/GPL/NPSL/LGPL）必须 `lic_mode=cli_subprocess`，`active-high/cloud` 必须 `requires_authz=true`；工具镜像 tag 锁定禁 `latest`。
- `EASM_DEV_TOKENS` 未设时全部请求 401（只 warn）；`EASM_ENV=production` + dev 令牌 = 拒绝启动（V-8；对外环境必须 OIDC/ENH-07）；`EASM_SINGLE_USER=1` 要求恰好一枚 dev 令牌（admin）或 OIDC；`EASM_REQUIRE_CONFIRMATION` **默认开启**（`=0` 显式关闭），`scan:port`/`scan:dir`/`notices` 需 `X-EASM-Confirmation`（先 `POST /v1/confirmations`），MCP `scan_active` 同闸（`confirmation_id` 参数或同名头）；迁移由 `cmd/migrate` + `schema_migrations` 管理（新增文件后 `make migrate` 自动应用）；清场 SQL 不得与 `make test-integ` 并发执行（会中途删测试数据造成假失败，2026-10-18 实测一次）；外部签字项（G8-02 报送通道 / G8-03 暗网源 / G8-04 法务白名单 / G8-05 试点签署 / G8-06 SRE 签字）属外部动作，不得代签。
