<p align="center">
  <img src="./assets/readme/hero.svg" width="100%" alt="Lumina · 烛隐 EASM——互联网敏感信息过度泄露排查平台，五阶段外部攻击面管理流水线">
</p>

<div align="center">

**Lumina · 烛隐 EASM** —— 互联网敏感信息过度泄露排查 / 外部攻击面管理平台

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/anyeduke11/lumina-easm/actions/workflows/ci.yml/badge.svg)](https://github.com/anyeduke11/lumina-easm/actions)
[![Version](https://img.shields.io/badge/version-v0.0.2-blue)](https://github.com/anyeduke11/lumina-easm/releases)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)

</div>

---

> **架构方向（v1.1）**：平台正从「五阶段台账」演进为「监管单位单用户 + 被监管单位数据域」的 AI-native EASM；Phase 0 已恢复绿色（`go build`/`go test` 通过），单用户化仍在推进。目标架构、单用户安全补偿与收口清单见 [docs/architecture/EASM-ARCH-OPT-v1.1.md](docs/architecture/EASM-ARCH-OPT-v1.1.md)。

## 这是什么

监管五阶段驱动的**外部攻击面排查平台**：对组织的互联网敏感信息过度泄露进行系统化排查、取证、处置与合规报送，覆盖**搜索引擎 → 空间测绘 → 端口目录 → 第三方渠道 → 暗网兜底**五条巡检线。

平台把「证据」放在第一位：每一条台账结论都可回溯到原始证据（WORM 固化、哈希锚定），零误报三重门与授权一票否决保证**结论可验证、闭环不虚报**。

## 为什么不同

| 设计公理 | 在代码中的落点 |
| --- | --- |
| **AX-1** 数据是地基（图谱） | 资产入账即投影为图谱实体，图谱是资产清单的母体 |
| **AX-2** 确定性发现 + AI 判断 | 平台只做确定性规则/CLI；敏感识别走 22 条规则；AI 为 Provider 接缝（ENH-03：SenseNova 装配，AI 结论不入台账） |
| **AX-3** 一切皆可验证 | 证据先行：`evidence.Store` WORM，`raw_ref`/`snapshot_ref` 可回溯；台账闭环必须经复测 `Verify`，未装配 verifier 返回 501——**禁止伪造闭环** |
| **AX-4** 持续闭环 | 台账四态状态机；处置工单五态（待整改→处置中→已通报平台→已下架→已处置），跳步/回退/终态出边全拒 |
| **AX-5** 人在环可审计 | 四类高危动作（爆破/主动扫描/跨被监管单位读取/对外通报）强制人工确认；audit 仅追加；通报三要素列锁定 |
| **AX-6** 一切皆插件 | 平台零扫描逻辑，工具经插件契约注册，CLI 子进程为原定契约 |

三个最容易造假的地方，全部被闸卡死：

- **授权一票否决**：无有效授权（有效期/时间窗/范围）→ 巡检直接拒绝并落审计，任何一步不伪造成功。
- **零误报三重门**：`严重`须 ≥2 独立信源（V-5）＋ 反证必答（V-10）＋ 复测证据闭环（S-2）；不满足自动降级并留痕。
- **无法静默降级**：env 设置但装载失败一律 `log.Fatalf`；可选能力未装配返回 501 + machine-readable code，不返回空数据。

## 工作原理

<p align="center">
  <img src="./assets/readme/workflow.svg" width="100%" alt="Lumina 全链路闭环：五阶段排查 → 采集与判定引擎 → 台账三重门 → 处置/通报/报告，授权一票否决贯穿全程">
</p>

五阶段巡检线（口径唯一：步骤数 4/4/5/3/4）：

| 阶段 | 内容 | 入口 |
| --- | --- | --- |
| P1 搜索引擎 | 主动搜索 + 语法库检索，发现暴露面 | `search` |
| P2 空间测绘 | 域名/IP/证书/端口关联，指纹基线 | `footprint` |
| P3 端口目录 | 主动扫描（repo/port/dir），授权闸前置 | `collect` |
| P4 第三方渠道 | 代码托管/GitHub 泄露源持续监控 | `collect` |
| P5 暗网兜底 | 样本巡检 → 归属判定 → 量级区间 → 交易链路 → 线索包固化 | `darkweb` |

采集结果统一归一为 `easm.candidate.v1`，判定命中的写入台账 `L-*`；台账是唯一事实源，三重门过滤后流向处置工单、线索通报（公安 24h / 省通报中心 48h，回执才置已报送）与四受众报告（管理层/运营/合规/红队）。

## 快速开始

前置：Go 1.24。

```bash
git clone https://github.com/anyeduke11/lumina-easm.git
cd lumina-easm

make run        # 纯内存模式起 server（dev 令牌演示，默认 :8087）
```

打开 `http://localhost:8087` 即可使用 console。纯内存模式不预置数据；当前可直接建资产（`POST /v1/assets`）。被监管单位（`/v1/entities`）已提供，`/v1/tenants` 保留为兼容别名。Dev 令牌仅本地有效：

```bash
EASM_DEV_TOKENS="tok-admin:R7:*" make run
```

console 为七模块操作流：风险总览（含单位风险汇总）、监测与预警、排查（范围→授权单校验→五阶段逐单位下发）、知识支撑、AI 集成与调用、报告中心、设置与日志；默认浅色主题。实时面仅在真实数据就绪时标注「实时」，空库与示例数据显式标注（CSV 导出带「示例-」前缀），不伪造下发/导出结果。

PostgreSQL 模式（entity 数据域隔离；单用户监管形态的目标）：

```bash
make migrate    # 应用 migrations/001–030（PG 需 brew services start postgresql@18）
make run-local  # EASM_PG_DSN 模式
make run-jobworker  # 另开进程消费 discovery 任务（需 EASM_PG_DSN）
```

## 单用户监管模式（Phase 0）

- **单操作员**：`EASM_SINGLE_USER=1` 要求恰好一枚 `EASM_DEV_TOKENS`，角色固定 admin；多账号入口不对外暴露。
- **entity 数据域**：对外资源统一走 `/v1/entities`（兼容 `/v1/tenants` 别名）；`tenant_id` 保留为 entity 数据域 legacy 列，RLS 继续生效；迁移 `023` 提供 `regulated_entities` 视图。
- **高危动作确认**：`POST /v1/confirmations`；默认开启（`EASM_REQUIRE_CONFIRMATION=0` 显式关闭），`scan:port` / `scan:dir` / `notices` 需携带 `X-EASM-Confirmation`，MCP `scan_active` 同闸（`confirmation_id`）；迁移 `024` 落确认表。
- **配置与组装根**：`internal/config` 集中装载/校验 env；`internal/app.Deps` 作为组装根，替代 28 参数 `newRouter`。
- **迁移工具**：`make migrate` 走 `cmd/migrate` + `schema_migrations`；`make migrate-status` 查看状态；既有库首次接入用 `make migrate-baseline`。
- **OpenAPI**：`docs/api/openapi.json` 由路由表生成；`make openapi` 生成并校验覆盖（`/v1/entities` 与 `/v1/tenants` 别名）。
- **认证**：生产 OIDC（`EASM_OIDC_*`）；`cmd/breakglass` 生成应急凭据（`EASM_BREAKGLASS_HASH`）；`cmd/passkey` 生成 ES256 passkey（`EASM_PASSKEY_PUBLIC_KEY`，challenge-response step-up）。
- **CI 四门禁**：build/vet/unit → migrate + app-role integration → OpenAPI 覆盖 → trace + lint。

## Phase 1 EASM 核心

- **资产身份/观察流**：`POST /v1/entities/{id}/observations` 写入 append-only 观察；`inventory` 按 canonical key/别名归并为规范资产，保留来源与时间；`GET /v1/entities/{id}/inventory` 查看当前态。
- **发现 Connector**：`POST /v1/entities/{id}/discovery` 入队 `seed` / `ct` 任务；worker 执行 Connector → Observation → Asset → Exposure Graph（`owns` 等边）；Observation 可携带 FindingHint，由平台创建 Finding。
- **Job Queue**：PG `SKIP LOCKED` 租约、幂等键、重试/死信；`GET /v1/entities/{id}/jobs` 查看，`POST .../jobs/{jid}/cancel` 取消；独立进程 `make run-jobworker` 消费。
- **Finding 生命周期**：`POST /v1/entities/{id}/findings` 创建；`.../validate` 记录验证（confirmed 必须有 `evidence_ref`）；`.../close` 仅 confirmed/verified 且必须有证据。
- 迁移 `025`–`027`：inventory / findings / jobs；内存与 PG 双实现，PG 集成测试覆盖。

## Phase 2 检测与运营闭环

- **DNS / ASM Connector**：`dns` 解析 A/AAAA/CNAME 并写入 `resolves_to` 边；`asm` 通用外部 ASM feed 适配器（`EASM_ASM_URL` / `EASM_ASM_TOKEN`，未配置不注册）。
- **Finding 自动生成**：`internal/detect` 复用 22 条判敏规则，观察值 + payload 命中即创建 Finding；high/critical 自动告警。
- **Finding→ledger 投影**：`POST /v1/entities/{id}/findings/{fid}/project`；confirmed/verified 才可投影，严重级仍走台账门1/门2，幂等。
- **资产状态机**：`POST /v1/entities/{id}/inventory/{aid}/state`；`candidate → confirmed → active ↔ stale → retired`，retired 必须给原因。
- **告警**：`GET /v1/entities/{id}/alerts`、`POST .../alerts/{aid}/ack`；迁移 `028`/`029`。
- **前端**：资产视图新增身份资产 / Finding / Job / 告警四张实时表；失败按表标注，不静默降级。

## Phase 3 运营与治理增强

- **告警通知通道**：Finding 告警可经既有 `notify` 统一出口推送（webhook/mail/soar）；`POST /v1/entities/{id}/alerts:dispatch`；保留高危过滤、去重、失败上浮。
- **Finding 批量运营**：`POST /v1/entities/{id}/findings:bulk` 支持 `confirm` / `close` / `project`，返回逐条失败原因；批量投影仍走台账门1/门2。
- **资产自动衰减**：jobworker 周期扫描 `EASM_ASSET_STALE_AFTER`（默认 720h）/ `EASM_ASSET_RETIRE_AFTER`（默认 2160h）；也支持 `POST /v1/entities/{id}/inventory:decay` 手工触发。
- **Cloud / 第三方 Connector**：`cloud` 复用通用 feed 契约（`EASM_CLOUD_URL` / `EASM_CLOUD_TOKEN`），未配置不注册。
- **前端筛选/分页/报表联动**：四张运营表支持关键字筛选、分页；Finding 行内“投影台账”；告警通道选择与推送；报告中心入口。

## 仓库结构

```text
platform/services/cmd/server      REST /v1/* + MCP /mcp + console 静态面
platform/services/cmd/worker      Temporal activity worker
platform/services/cmd/jobworker   Phase 1/2 发现与判敏 Job Worker（PG 队列消费）
platform/services/internal/       业务域分包（inventory/finding/job/connector/discovery/detect/projection/alert/sweep/ledger/...）
console/                          零依赖纯静态前端（index.html + app.js + easm-live.js）
migrations/                       001–030 顺序 SQL（含 entity 视图、确认表、inventory/findings/jobs/alerts、资产状态、sweep 限速留痕、RLS 与最小权限角色）
scripts/                          端到端验证 / 压测 / 许可证取证 / 追溯对账
.github/workflows/ci.yml          四门禁：build/vet/unit → migrate+PG integration → OpenAPI → trace+lint
```

## 测试与验证

```bash
make test        # go test ./... -count=1
make trace       # C-1 追溯对账：每个 Go 包注释须携带 FR/WP/IR/CR/ENH 编号
make test-integ  # 集成测试（需 EASM_PG_DSN，easm_app 角色）
make verify      # 收口套件：集成回归 + 端到端三件套 + 授权 SOP 预演
```

端到端脚本要求 server 监听 `:18080`：`live-smoke.py`（前端接线回归）、`kb-smoke.sh`、`authz-sop-drill.sh`、`workorder-live.sh` / `notice-live.sh` / `darkweb-demo.sh` 等。

## 架构演进

当前架构体检、目标架构与 12 个月优化路线见 [docs/architecture/EASM-ARCH-OPT-v1.1.md](docs/architecture/EASM-ARCH-OPT-v1.1.md)。v1.1 按「监管单位单用户」形态更新，包含被监管单位数据域、单用户安全补偿与 Phase 0 收口清单。

## v0.0.2 边界（已知未交付项）

- **读口与越域**：读端点按主体作用域过滤，越域返回 403 并落 deny 审计；`/v1/monitors`、`/v1/candidates/unsupported` 为平台级只读面，要求管理域权限。
- **采集前置校验**：`scan:repo`/`scan:port`/`scan:dir` 在执行前校验目标与端口语法（拒绝选项注入），字面量 IP 先过细目标闸；工具未安装返回 501 `tool_unavailable`（能力缺失不伪装成扫描失败）。
- **认证**：单用户 dev 令牌默认；OIDC（RS256/JWKS）、break-glass、passkey（ES256 step-up）已提供（Phase 0）。生产建议启用 OIDC 并禁用 dev 令牌；完整 WebAuthn 为 Provider 替换。
- **暗网 feed**：真实暗网数据源为软阻塞（G8-03），当前以模拟 fixture 兜底入口。
- **报告导出**：Markdown / JSON / PDF（PDF 为零依赖确定性 writer；字体缺失=501 诚实边界）。
- **真实通报通道**：对外报送（G8-02）未触达，系统生成单号+模板材料，「已报送」仅能由回执录入。
- **复测沙箱**：真实微 VM 池（ENH-10）为外部环境项；当前以 `EASM_VERIFY_CMD` 简单隔离或 HTTP Provider 接缝运行。

## License

[Apache License 2.0](LICENSE)
