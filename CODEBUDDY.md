# CODEBUDDY.md This file provides guidance to CodeBuddy when working with code in this repository.

## 项目概览

Lumina「Sentinel EASM」——互联网敏感信息过度泄露排查 / 外部攻击面管理平台。Go 1.24 单模块（`github.com/wangdev88/easm-platform`），依赖极少（`lib/pq`、`minio-go/v7`、Temporal SDK），HTTP 层直接用标准库 `net/http`（Go 1.22 `ServeMux`），无 Web 框架。业务代码全部在 `platform/services/internal/` 按域分包。

**当前版本：v0.0.1**（公开仓库 `anyeduke11/lumina-easm`，README/CHANGELOG 随代码入库）。版本号与发布说明维护在 `CHANGELOG.md`；涉及对外能力变更时同步更新 README「v0.0.1 边界」一节。仓库模块路径 `github.com/wangdev88/easm-platform` 为历史既定值，未随公开仓库改名——改动前不要擅自替换。

上位依据是《互联网敏感信息泄露排查》工作文件：监管五阶段（P1 搜索引擎 / P2 空间测绘 / P3 端口目录 / P4 第三方渠道 / P5 暗网）、三类敏感数据（34 项 / 22 条规则）、整改工作建议。

## 常用命令

```bash
make build / test / vet / lint / trace  # go build|test ./... | go vet | golangci-lint | C-1 追溯对账
make test-integ                       # 集成测试：EASM_PG_DSN=easm_app 角色跑全量 ./...
make migrate                          # 按序 psql 应用 migrations/001–018（管理员 DSN；新迁移必须同步 Makefile，否则集成测试 42P01 暴露）
make run-local                        # 本地 PG 模式起 server（默认 :8080）
make run                              # 纯内存模式起 server（dev 令牌演示）
make run-worker / temporal-dev        # Temporal worker / 本机 dev server（:7233）
make verify                           # 收口套件：test-integ + kb-smoke + live-smoke + authz-sop-drill
make backup / dev-up / dev-down       # pg_dump 快照 / docker compose dev（compose 暂缓）
```

单测：`go test ./platform/services/internal/sweep/ -run TestService -v`。
集成测试：`EASM_PG_DSN=postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable go test ./platform/services/internal/pgstore/ -count=1`。

端到端脚本：**server 必须监听 `:18080`**（`PORT=18080`，与默认 8080 不一致是常见坑），默认 Bearer `tok-admin`：`kb-smoke.sh`（知识库）、`live-smoke.py`（前端接线回归）、`authz-sop-drill.sh`（授权 SOP 预演）、`workorder-live.sh` / `notice-live.sh` / `darkweb-demo.sh` / `darkweb-persist-drill.sh` / `notice-chain-live.sh`（M2 各域 live）、`crash-drill.sh`（Temporal 断点续跑）、`g806-bench.py`（压测）、`g804-license-check.py`（许可证取证）、`verify-local-demo.sh`（门3 简单隔离复测契约样例，配 `EASM_VERIFY_CMD` 装配）。

## 上位文档与编号体系

权威文档在仓库外随项目归档分发：《总体设计方案》v3.0、《PRD》、《SRS》、《详细开发计划》v1.2、《GAP-8 待确认项调研清单》、《M0/M1 收尾核查表》。**改动代码前先查其中的编号依据**。

- 追溯链（C-1 编号闭合）：PRD 功能点 F1–F18 → SRS 的 FR/DR/IR/NFR/CR。包注释与提交信息携带 FR/WP/IR 编号，新增实现须回写追溯，不留孤儿需求。
- 口径唯一：五阶段 P1–P5 步骤数 **4/4/5/3/4**；子能力码 STR-1~5 / MAP-1~4 / SCAN-1~5 / EXT-1~3 / DRK-1~2；工具输出统一归一为 `easm.candidate.v1`（kind ∈ asset/finding/lead，解析失败进 `unsupported` 保留原文+原因）；风险四因子默认权重 30/30/25/15。
- **SRS §10 十一条一票否决**（任一条违反即不予发布，改动相关代码前必读）：五阶段覆盖不全；34 项/22 规则缺失；台账必填字段可绕过；跨租户串权；通报超时无标识无升级；扫描授权可绕过；内网不可用；首屏 >3s；严重级结论不可验证（AX-3）；插件破坏主干或平台含工具专有扫描实现（AX-6）；高危动作无人工确认（AX-5）。

## 架构

### 六条设计公理 → 代码约束

| 公理 | 在代码中的落点 |
| --- | --- |
| AX-1 数据是地基（图谱） | `internal/graph` + `ingest.Projector` 资产入账即投影；图谱是资产清单的母体 |
| AX-2 确定性发现 + AI 判断 | 平台只做确定性规则/CLI；判敏走 `internal/classify` 22 规则；AI 未接入（ENH-10） |
| AX-3 一切皆可验证 | 证据先行（C-5）：`evidence.Store` WORM，`raw_ref`/`snapshot_ref` 可回溯；ledger `closed` 必须经 `Verify`，未装配 verifier 返回 501（禁止造假闭环） |
| AX-4 持续闭环 | ledger 四态状态机；workorder 五态（待整改→处置中→已通报平台→已下架→已处置，跳步/终态出边全拒=不可虚报闭环） |
| AX-5 人在环可审计 | 四类高危动作（爆破/主动扫描/跨租户读取/对外通报）强制人工确认；audit allow/deny 全量仅追加落 PG；notice 三要素列锁定 + DB 触发器 |
| AX-6 一切皆插件 | 平台零扫描逻辑；工具经 `internal/plugin` 8 字段契约注册，CLI 子进程是原定契约（容器=生产加固选项，ENH-08） |

### 进程与装配

两个 `main`：`cmd/server`（REST `/v1/*` + MCP `/mcp` + console 静态面）与 `cmd/worker`（Temporal activity worker）。装配全部发生在 `cmd/server/main.go` 的 `main()`，无 DI 框架——顺序构造各 `Service` 后手工传给 `httpapi.New(...)` / `mcp.New(...)`。两条铁律不可破坏：

1. **env 设了但装载失败一律 `log.Fatalf`（fail loud），拒绝静默降级**：`EASM_PG_DSN`、`EASM_TEMPORAL_HOST`、`EASM_EVIDENCE`（仅 `file|minio`）、KB 接 PG。
2. **可选能力未装配时端点返回 501 + machine-readable code**（`collect_unavailable`、`graph_unavailable`、`verifier_unavailable`），不返回空数据；也不得伪造（如 `notice_persisted:false` 如实标注）。

### 双后端：内存 ↔ Postgres

`EASM_PG_DSN` 是否设置决定分叉：内存模式 = 各域 `NewMemStore()`（单测/演示用）；PG 模式 = `pgstore.Open(dsn)` 统一替换 store，并挂上仅 PG 侧能力（`Tenants`、`Assets`、`Ledgers`、`KB`、`Sweeps`、`Authz`、`WorkOrders`、`Notices`、`Reports`、`Audit`、`Graph`、`Snapshots`、`NotifyLog`、`Darkweb`、`OwnershipQueue`、`Candidates`）。

因此**每域定义自己的 `Store` 接口 + 内存实现**，PG 实现集中在 `internal/pgstore/`（一个 `DB` 句柄派生 16 个 store）。新域照此模式：接口在域包、实现在 `pgstore/<域>store.go`、装配写在 `main()`（内存 store 声明 + PG 分支赋值两行都要写）。**注意 `ledger` 的 PG 实现是显式列而非 JSONB——`Item` 新增字段必须同步「迁移列 + Create + Update + `scanLedger` 目标参数」四处：不加列=静默丢字段（内存正常的双后端漂移），漏 Scan=运行期 500。Plain `go test` 会 skip 集成测试从而掩盖，必须 `make test-integ` 验证（V-5/V-10 各实测一次）。**

RLS 语义（`pgstore.withTenant`）：事务内 `set_config('easm.tenant_id', ...)`；`ListByTenant` 设真实 tenant 行过滤，`Get` 设空串显式穿透、跨租户可读后由 Service 层 `InScope` 判 403 + deny 审计（内存/PG 契约一致，C-6）。**应用 DSN 必须是 `easm_app` 角色**（无 BYPASSRLS，`002_role_app.sql`），管理员 DSN 跑服务会让 RLS 静默失效。迁移 `001–018.sql` 按文件名序手工应用（无版本表），每个迁移自带 `GRANT ... TO easm_app`；schema 双份实现时注意同步。注意个别端点按设计返资源级 404（如 `ownership/fingerprints` 未登记基线不伪造空基线）——判「路由是否存在」要用 OPTIONS（405=在/404=不在），不能用 GET。

### HTTP 层

`internal/httpapi/server.go` 的 `Handler()` **集中注册全部路由**（其他文件只提供 handler），用 `Option` 函数选项（`WithLedger`、`WithDarkweb`…）注入能力，未注入即 nil → 501。路由用 Go 1.22 模式语法（`GET /v1/tenants/{id}/assets`，`r.PathValue` 取值）。

鉴权链：`auth()` 中间件从 `Authorization: Bearer` 查 `EASM_DEV_TOKENS` 静态表（`token:role:t1|t2`，`*`=全部）得到 `rbac.Principal` 注入 context，不中即 401；handler 内再显式 `p.Can(Perm...)` + `scopeAssets`/`InScope` 做租户过滤。生产 OIDC 未接入（ENH-07 环境阻塞）。角色矩阵 `R1..R8` 在 `rbac/rbac.go`。顶层 `newRouter()` 分流：`/mcp` → `mcp`（JSON-RPC 2.0，只读 6 工具，token 表复用、Scope 工具层强制）；`/v1/*`、`/healthz` → api；其余 → `console/` 静态面。

### 五阶段工作流与治理闭环

核心链路：`POST /v1/sweeps` → `sweep.Service` 按 P1–P5 逐资产检测（台账反推去重集，账本=唯一事实源）→ 命中写 `ledger`（`L-<年>-<序号>`；外部采集 `L-EXT-<sha12>`、扫描 `L-SCAN-*`、暗网 `L-DRK-*`）。`collect`（scan:repo/:port/:dir，gitleaks/nmap/ffuf 子进程）与 `darkweb`（线索包 `LPK-*`）是并行采集入口；`ingest.Projector` 把入账资产投影为图谱实体。

**授权闸是一票否决⑥**：`sweepSvc.SetScope(authzSvc)` + `collect`/`darkweb` 各自 `authz.Validate`（有效期/时间窗/排除项/端口收窄/二次授权），主动渠道另有 `CheckTarget` 细目标闸与 `rate_limit`→工具参数（nmap `--max-rate`/ffuf `-rate`）消费。**编排层限速接缝（S-1 销账）**：`sweep.Service.WithLimiter(authzSvc)`——每次执行读一次 scope，执行行回显 `rate_limit` 并在资产判定轮间施加令牌桶步间最小间隔，等待毫秒 per-run 累计写 `paced_ms`（**必须 per-run 归属，不得放 Service 级字段**：跨 sweep 累计=别行的等待写进本行=取证失真，曾实测暴露并以 `TestSweepPacedMSIsPerRun` 虚拟时钟守卫锁定）。

**零误报三重门**（门1/门2 在 `ledger.Create` 统一执行，所有入账路径共用，旁路无门；门3 在 `Verify`）：
- 门1（V-5）：`Level=严重` 须有 ≥2 个独立信源（`Item.XChk`），否则降「高」+ 留痕 + `ledger.gate1_downgrade` 审计；
- 门2（V-10）：`严重` 须有已回答的反证（`Item.Refute`：claim/outcome/evidence），无回答降「高」、反证成立（confirmed）降「中」，均留痕 + `ledger.gate2_downgrade` 审计；
- 门3（S-2）：闭环必须经 `POST /v1/ledger/{id}/verify`——`Verification`（method/result/verifier/evidence_ref）写入 `Item.Verifs`（`018` jsonb 列）；`reproduced` 必带 `evidence_ref`（C-5）→closed，refuted/inconclusive→doing；manual/cross_tool=人在环可用，**sandbox 走 `Verifier` provider 端口，两种 Provider（接缝不变、替换装配）**：① `EASM_SANDBOX_URL`→`verifier.Sandbox`（HTTP 前端 provider，回执硬闸=result 枚举+reproduced 必带 evidence_ref，非 200/回执残缺一律上浮；ENH-10 微 VM 池本体=外部环境项）；② `EASM_VERIFY_CMD`→`verifier.Local`（**简单隔离**=ulimit 文件写空间+nice 压低优先级+超时+一次性工作区，产物 tar 入 evidence WORM；复测契约=`<cmd> <item_id> <tenant> <workdir>`，工作区写 `result.txt` 为唯一裁决出口，样例 `scripts/verify-local-demo.sh`）；两者互斥（HTTP 优先）；都未设→501 `verifier_unavailable` 禁止冒充闭环。
信源/反证由 sweep（资产在用状态）、collect（示例夹具路径 / HTTP 有效性）、REST（`xchk`/`refute` 字段）供给。

**ledger 是下游读口闸**：`workorder`（五态 + 必挂同租户真实台账条目，`WO-<sha12>`）、`notice`（线索通报 `NB-<sha12>`，公安 24h/通报中心 48h，A-08 超时催办，回执锁定，`/notices/{nid}/chain` 交付包逐项 sha256 可独立复核）、`report` 都以台账条目存在且同租户为前置。闭环只认真实复测，`verify` 未装配即 501。

外部依赖经 env 切换且接缝稳定：`evidence.Store`（`file`/`minio`）、`notify`（`EASM_ALERT_WEBHOOK`/SMTP）、`httpapi.SweepDispatcher`（Temporal 或进程内回退）。

### Temporal 与后台

设 `EASM_TEMPORAL_HOST` 即装载 `tdispatcher`（TaskQueue `easm-sweep`，Workflow `SweepWorkflow`），否则进程内同步执行；server 与 worker **必须共享同一 `EASM_PG_DSN`**（worker 侧为空直接 fatal）。activity 用顶层函数注册并返回 string（SDK v1.42 结构体活动/void 返回有已知坑，见 `cmd/worker/main.go` 注释）。诊断开关 `EASM_WORKER_ECHO=1`、`EASM_ACTIVITY_CRASHAT=N`。`monitor.Service.Start()` 起进程内定时 loop（R7 全量主体取数、请求级仍按主体过滤），diff 基线存 `Snapshots()`。

### 前端

`console/` 纯静态单页：`app.js` 是演示数据与视图渲染（不发起真实请求），`easm-live.js` 是真实数据水化层（IIFE 注入令牌条，`api()` 统一加 Bearer，默认 `tok-admin`）。`live-smoke.py` 守护接线：`easm-live.js` 引用的每个 `/v1/` 路径必须在路由表存在，并对 43 个租户级端点做双向守卫（路由存在 + JS 引用；OPTIONS 405/404 判别），同时断言 M2/S-3 导航徽标挂载点（`navWoCount`/`navNoticeCount`/`navPkgCount`/`navRptCount`）与接线函数（`setPill`/`easmJumpTo`）——徽标实时计数（null=隐藏=无数据不留 0 噪音），视图内跳转按钮共用 `easmJumpTo`。视图 h2 静态徽标默认「示例」，live 层 hydrate 成功升级为「实时」（`markLive`）——未接视图保持「示例」，页内可区分真实/示例。合规报送卡片的按钮必须派发到真实路径（`easmComplianceAct`），禁止 toast 虚构「已生成/已审批」。

### 路线图与增强项（ENH）登记

M0 基座、M1 排查治理已收尾（D1 签认「内部验证形态 MVP 达成」）。**M2 确定性范围全部交付并收口**：M2-01 collect 三渠道、M2-02 暗网兜底（真实 feed 待 G8-03）、M2-03 工单、M2-04 通报与证据链、M2-09 报告中心（导出 md/json/**pdf** 三格式——PDF 为零依赖确定性 writer + **字体子集化**（glyf/loca 重建+复合组件 GID 重映射，29MB→126KB），字体缺失=501 诚实边界）、FR-CHN-007 线索包导出面均已交付；审查后修订轮 V-1~V-10 完成；**S 批完成（S-1 rate_limit 销账、S-2 门3 前置=018、S-3 四视图接线、S-4 沙箱接缝、S-5 简单隔离=`EASM_VERIFY_CMD`；BUG-06/07 入册）**。**M2 剩余全部为外部项**：M2-05~08/10 阻塞于 ENH-10（外部环境+签字；装载缝 `EASM_SANDBOX_URL` 就绪=零代码改动）、G8-02 定稿后通报格式细调（挂接点=`RenderPackageMD`+notice chain 渲染，单点）、G8/K 系列签字（不代签）。**M3 进行中（开发计划 §16）**：WP-M3-02 三重门已被 M2 提前交付（仅剩 ENH-10 真实形态）；**M3-A 已交付**——`internal/scoring` 四因子评分确定性核（暴露可达 30/可利用性 30/资产重要性 25/凭据有效性 15，明细含依据、贡献和=总分可复算），端点 `GET /v1/tenants/{id}/assets/{aid}/score` 与 `GET /v1/tenants/{id}/scoring/weights`，权重/阈值经 **`EASM_SCORE_WEIGHTS`/`EASM_SCORE_THRESHOLDS`** 注入（非法装载即拒，默认标注「待 G8-01 定稿」=GAP-8 定稿后仅换配置）。**M3-B 已交付**——`graph.PathQuery` 端口 + 双实现（`MemPath` Go BFS / `pgstore.PGPath` 递归 CTE；**排序去重共用 `graph.RankPaths`**=切后端不换结论，集成测试同图对账真 PG 跑通），端点 `GET /v1/tenants/{id}/graph/{paths,reach,subgraph,top-paths}`（未装配=501 `graph_path_unavailable`），内存模式补齐 `graph.NewMemStore` 图谱后端（此前 501）；路径直出边序/跳数/目标种类/缓解建议（11 类关系全覆盖）/入选理由，默认深度 6、TopN 5；**登记缺口**：图谱边当前仅 `resolves_to`（资产投影），`leaks`/`valid_on` 等边无写入方→真实数据下 Top5 恒空（如实返空，M3-C 联动闭合）。**M3-C 已交付**——① `internal/secret` 密钥有效性三档（context 占位/示例路径 → format 已知形状+长度+字符集 → probe 非破坏 GET 外呼，`EASM_SECRET_PROBE=1` 显式开启，默认关闭）+ 五状态（valid/revoked/invalid/unverifiable；**未外呼=unverifiable，不把「看起来像」当可用**）+ 度量端点（分母/分布/误报率/**口径**），端点 `POST /v1/tenants/{id}/secret:verify`、`GET /v1/tenants/{id}/secret/metrics`；**图谱边供给=仅 valid 凭据连 `leaks` 边**（闭合 M3-B 缺口：Top5 由 0 条→真实 1 跳）；密钥明文不入库不回显（仅脱敏+位置）；② `internal/shadowit` 影子 IT 收敛建议（复用 `ownership.Judge`）+ 纳管人审面，端点 `POST /v1/tenants/{id}/shadow:{advise}`、`POST /v1/tenants/{id}/shadow/admit`；**红线落代码**：建议无副作用、疑似动作集不含 admit、纳管双闸（判定归属+reviewer，疑似纳管 409 `not_owned`、缺人审人 400 `review_required`）。登记缺口：密钥自动投递通道（gitleaks `--redact` 不落密钥值）、JWT/私有形状判据、外呼 `rate_limit` 消费（`Pacer` 端口已预留）。**M3-E 已交付**——`internal/evalset` 评测集与反馈门禁骨架（WP-M3-06/FR-VRF-004/AIL-7）：样本（`Subject` 端口，现仅装配确定性判敏引擎 `classify-22rules`）+ 指标（F1/κ/误报率/幻觉率，全部由混淆矩阵复算）+ **放量门禁**（阈值 5 元组 `EASM_EVAL_THRESHOLDS` 注入非法即拒；无记录=fail closed；按当前口径重算、`run.gate` 仅运行时快照）+ **台账回流**（Refute confirmed/复测 refuted→误报样本、最近复测 reproduced→真阳性、refuted 信号优先、inconclusive/无信号跳过留痕；EV-<sha12> 幂等），端点 7 个（`evalset/{samples(GET,POST),relabel,reflux,runs,gate}`、`evalset:run`），迁移 `019_evalset.sql`（Makefile 已同步），幻觉率口径=无证据阳性结论占比（AI 面预留，接缝不变）。**M3 收口核查完成（开发计划 §16.9）**：M3 确定性范围（A/B/C/E）收口达成——机械验证全绿（test/integ 33 包、trace-check、kb-smoke、live-smoke 49 项、authz-sop-drill 五步+撤回，演练脚本撤回 valid_to 时间炸弹已改动态日期）；M3 剩余全部外部项：M3-D 多模态与 M3-C-AI 文案、灰度放量动作面=ENH-03（消费 `evalset/gate` 判定，接缝就绪），G8-01/ENH-10 定稿=仅换配置/换 Provider，不代签。

ENH-01~10 是取消/延后方案的正式 backlog（Temporal/Neo4j/向量/Redis/MinIO/ClickHouse/OIDC/容器/K8s/Harness）。**机制：接缝不变、Provider 替换**——启用某项 = 在既有接口挂新 Provider + 契约测试，上层零改动；未启用项在界面/文档显式标注能力边界，不静默降级。

本地化约束（开发计划 §14）：开发机无容器，**PG 是唯一必需外部依赖**；Temporal/MinIO 走 brew 非容器；`psql`/`pg_dump` 路径硬编码 `/opt/homebrew/opt/postgresql@18/bin/`。

## 开发约定

- **TDD 红→绿→变异验证**（项目固定纪律）：每个功能/修复先写失败测试，再实现，最后做变异验证（故意破坏实现确认测试能捕获），结果记入文档进展日志。缺陷修复须补提交级守卫断言（参考《缺陷回归用例集》与 `sweep` findings 双断言先例）。
- **fail loud 优于兜底**：装配失败、存储失败、授权缺失一律上浮或拒绝；禁止半可用状态（如「材料出了但查不到」）、禁止伪造数据冒充真实（合成单号、空基线伪装等先例均已按此修正）。
- **口径同步**：运行时消费缺口要如实登记再闭合（如 `time_window`/`rate_limit` 先登记缺口后消费）；文档与代码同批提交，「纯文档登记轮」是常规轮次。
- 测试约定：绝大多数 `*_test.go` 零外部依赖（`httptest.NewServer` + 内存 store），`go test ./...` 不要求 PG；PG 集成测试统一 `*_integration_test.go`，首行 `if os.Getenv("EASM_PG_DSN") == "" { t.Skip(...) }`，`t.Cleanup` 清 `itest-%` 残留；测试基建 `httpapi/server_test.go` 的 `newTestServer(t)`（双租户 + R7/R1/R5 三令牌），跨租户用例同时断言 403 与 deny 审计；表驱动断言错误哨兵值（`authz.ErrNotInScope` 等）；安全测试带「为什么」注释。
- CI（`.github/workflows/ci.yml`）：`go vet` → `go build` → `go test ./... -count=1` → `trace-check`（C-1 对账）→ golangci-lint（blocking）。新增包必须在包注释携带 FR/WP/IR/CR/ENH 编号。
- 插件合规护栏：传染性许可证（AGPL/GPL/NPSL/LGPL）必须 `lic_mode=cli_subprocess`，`active-high/cloud` 必须 `requires_authz=true`；工具镜像 tag 锁定禁 `latest`。
- `EASM_DEV_TOKENS` 未设时全部请求 401（只 warn）；`EASM_ENV=production` + dev 令牌 = 拒绝启动（V-8；对外环境必须 OIDC/ENH-07）；迁移需 001–018 全按序且同步 Makefile migrate 清单；清场 SQL 不得与 `make test-integ` 并发执行（会中途删测试数据造成假失败，2026-10-18 实测一次）；外部签字项（G8-02 报送通道 / G8-03 暗网源 / G8-04 法务白名单 / G8-05 试点签署 / G8-06 SRE 签字）属外部动作，不得代签。
