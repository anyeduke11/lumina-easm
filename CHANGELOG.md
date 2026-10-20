# Changelog

本仓库采用 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 格式，版本遵循语义化版本（[SemVer](https://semver.org/lang/zh-CN/)）。

## [Unreleased]

### Changed

- **console 七模块操作流重构**：导航收敛为「风险总览 / 监测与预警 / 排查 / 知识支撑 / AI 集成与调用 / 报告中心 / 设置与日志」，模块内上下文页签承载原有 19 个视图（旧视图 ID 与导航徽标挂载点全部保留）；默认浅色主题，主题偏好仍持久化于 `easm.theme`。
- **首页单位风险汇总**：总览页新增逐单位风险表（资产/严重/高危/待整改/待通报/五阶段覆盖/评分）与合计行，支持 CSV 导出（示例数据自动带「示例-」前缀）与直接跳转下发排查。
- **排查范围卡片**：选择单位后可读取该单位授权单（域名/IP/端口/排除项/有效期/限速/时间窗/二次授权/签署主体/授权书哈希），按 P1–P5 勾选逐单位下发 `POST /v1/sweeps`；部分拒绝如实回报，任一单位无有效授权即拒绝执行（一票否决⑥）。
- **设置与日志页**：数据源接入从顶栏抽屉迁入独立视图，展示令牌/健康探针（`/healthz`、`/readyz`）、单位与资产计数、最近排查任务与告警列表；审计为只写不可读，页面显式标注边界，不伪造日志流。旧 `settingsDrawer` 移除。
- **空库诚实态**：后端为空库时，示例租户不再充当真实作用域——排查下发禁用并提示建档，报告历史/线索包/台账显式显示「暂无客户」，CSV 导出标注「内置示例数据，非实时」；报告页徽标保持「示例」。

### Fixed

- **`/readyz` 被静态面吞掉返回 404**：顶层分流白名单仅放行 `/v1/*` 与 `/healthz`，API 路由表已注册的 `/readyz` 从未到达 API。现抽出 `isAPIPath` 并纳入 `/readyz`，附单测与变异验证（`internal/app/deps_test.go`）。

## [v0.0.2] - 2026-10-20

安全加固与可观测定版：收录单用户监管模式（Phase 0）、Phase 1–3 运营闭环，以及 M2 确定性采集/工单/通报/报告、M3 确定性评分/图谱/密钥有效性/影子 IT/评测集、M4 MCP 全量开放/计量预算/排查任务单等已交付能力；本版补齐深度审查发现的读口越域、MCP 高危确认、采集前置校验与双后端漂移缺口。

### Added

- **架构优化方案**：`docs/architecture/EASM-ARCH-OPT-v1.1.md`——监管单位单用户版；第一性原理体检、目标架构、双节奏业务流、五阶段重定位、12 个月路线图与 Phase 0 收口清单（含被监管单位数据域与单用户安全补偿）。
- **单用户监管模式（Phase 0）**：`EASM_SINGLE_USER=1` 单操作员；`/v1/entities` 一等别名（兼容 `/v1/tenants`）；`regulated_entities` 视图（023）；确认表与端点（024）；`EASM_REQUIRE_CONFIRMATION`（默认开启；`=0` 显式关闭）对 `scan:port` / `scan:dir` / `notices` 强制 `X-EASM-Confirmation`，MCP `scan_active` 同闸（`confirmation_id`）。
- **Phase 0 第二批**：`internal/config` 集中装载/校验；`internal/app.Deps` 组装根（替代 28 参数 `newRouter`）；`cmd/migrate` + `schema_migrations`；OpenAPI 生成/覆盖校验（`docs/api/openapi.json`）；CI 四门禁（build/unit、migrate+PG integration、OpenAPI、trace+lint）；OIDC（RS256/JWKS）、break-glass、passkey（ES256 challenge-response）。
- **Phase 1 EASM 核心**：`internal/inventory` 资产身份/观察流（规范资产+别名+append-only 观察）；`internal/finding` 生命周期（confirmed/closed 证据硬闸）；`internal/job` PG `SKIP LOCKED` 队列（幂等/重试/死信/租约回收）；`internal/connector`（seed / ct）与 `internal/discovery` 编排；`cmd/jobworker`；迁移 `025`–`027`；12 个 API 端点与 OpenAPI 覆盖。
- **Phase 2 检测与运营闭环**：DNS/ASM Connector；`internal/detect` 基于 classify 22 规则自动生成 Finding；`internal/projection` Finding→ledger 合规投影；资产状态机；`internal/alert` Finding 告警；前端资产/发现/告警实时表；迁移 `028`–`029`。
- **Phase 3 运营与治理增强**：Finding 告警通知通道（复用 notify webhook/mail/soar 三闸门）；`findings:bulk` 批量 confirm/close/project；资产自动衰减（jobworker 周期 + HTTP 手工触发）；cloud/第三方 Connector；前端筛选/分页/投影台账/告警推送/报告入口。
- **可运维性**：`GET /readyz` 真实依赖探活（PG `Ping`，2s 超时；失败 503 `not_ready`，回执不泄露 DSN/内部地址）；HTTP 全局 panic 兜底（500 `internal`，堆栈仅入服务端日志）；SIGINT/SIGTERM 优雅停机（停止接收新请求、10s 排水、关闭 PG 连接池）+ `IdleTimeout`。
- **CI 四门禁入库**：`.github/workflows/ci.yml`——unit（gofmt/vet/build/test）、integration（PG service + 空库全量迁移 + `easm_app` 角色集成测试）、OpenAPI（生成 + 覆盖校验 + 入库零漂移）、trace-check + golangci-lint（blocking）。

### Changed

- **默认服务端口 8080 → 8087**：`internal/config` 默认 `PORT`、`scripts/service.sh`、`scripts/start-all.sh`、`scripts/easm.env.example`、README/AGENTS 同步；端到端脚本仍固定 `:18080`（显式 `PORT=18080`，不受影响）。
- **全系统一键启停**：`scripts/start-all.sh` / `stop-all.sh` + `make start-all / stop-all / status-all`（PG→迁移→server→jobworker，`EASM_TEMPORAL_HOST` 已设时含 Temporal+worker）；`service.sh` 新增 `jobworker` 组件，env 文件先行加载（`EASM_PORT` 可覆盖默认端口）。
- **console 数据源接入迁入设置抽屉**：移除底部常驻浮动条（连接状态/令牌/重载），改为顶栏齿轮「设置」面板查看与操作，不再遮挡页面内容；`live-smoke` 增加设置抽屉挂载点与禁止重新注入浮动条的静态守卫。
- **console 品牌名统一为 Lumina EASM**：侧栏标题、页面标题、报告页脚、Copilot 名称与代码注释一并更名（漏洞库示例中的 Sentinel One 为受影响产品名，保持不变）。
- **平台定位收敛为内部单机形态**（不对对外服务、无需多账号）：容器/K8s 部署路线整体移除——删除 `deploy/`（docker-compose/helm/离线包清单/OPS 手册）、Makefile `dev-up`/`dev-down` 目标；插件契约移除 `Image`/`ResClass`/`LicMode` 字段（CLI 子进程为唯一执行形态），保留 `NetClass`×`requires_authz` 权限联动（C-4）。单用户监管模式已落地（见 Added）。

### Security

- **读端点域过滤**：`GET /v1/sweeps`、`GET /v1/sweeps/{id}`、`GET /v1/alerts`、`GET /v1/ownership/queue` 按主体作用域过滤，越域读返回 403 并落 deny 审计；`/v1/monitors`、`/v1/candidates/unsupported` 为平台级只读面，要求管理域权限（`PermManageTenants`）。
- **MCP 高危动作确认**：`scan_active` 与 REST 同闸（AX-5）——`EASM_REQUIRE_CONFIRMATION` 开启时须携带 `confirmation_id` 参数或 `X-EASM-Confirmation` 头；一次性消费，allow/deny 全量审计。
- **高危确认默认开启**：`EASM_REQUIRE_CONFIRMATION` 缺省开启，仅 `0/false/off/no` 显式关闭；确认服务未装配时拒绝放行（501 `confirmation_unavailable`），不静默降级。
- **采集执行前置校验**：`scan:repo` 拒绝空目录与选项注入；`scan:port` 校验目标/端口表达式，并在子进程前对字面量 IP 执行细目标闸；`scan:dir` 仅接受 http/https 且端口合法。工具未安装映射 501 `tool_unavailable`（能力缺失不伪装成扫描失败），语法非法映射 400 `invalid_request`。
- **sweep 限速留痕落 PG（迁移 030）**：`sweeps` 新增 `rate_limit`/`paced_ms`，与内存后端同契约——跨进程/Workflow 复盘可见限速是否被消费；`paced_ms` 保持 per-run 归属，不跨执行累计。
- **门1 信源独立性按通道计**：严重级「≥2 独立信源」改为按通道（rule/tool/evidence/http/human）去重——同一检测引擎的多条规则、`evidence:none` 不再互相作证；跨引擎/跨证据通道才满足门1，`XChk` 口径与降级留痕同步修正。
- **密钥探针 SSRF 防护**：`secret:verify` 外呼仅允许 http(s) 公网目标——字面 IP 静态拒绝 + 拨号前校验 DNS 解析结果（防 rebinding）+ 直连已验证 IP + 不走环境代理/不跟随重定向；环回/私网/链路本地/组播/CGNAT/保留段一律拒绝。内网验证端点须 `EASM_SECRET_PROBE_ALLOW_PRIVATE=1` 显式放开（且未同时开启探针时启动拒绝，避免静默无效的安全降级配置）；被拒外呼如实落 `unverifiable`，不当作可用凭据。

### Fixed

- **console livebar 误报「后端不可达」**：`app.js` 的 `toast` 是 IIFE 内函数，`easm-live.js` 裸调用 `toast(...)` 实际命中的是 `<div id="toast">` 的具名全局 DOM 元素（TypeError），异常又被接入层统一归因成后端故障。现经 `EASM.toast` 公共出口的本地包装调用；网络层失败标记 `err.network`，与接口错误/前端异常分开归因，并以 `console.error` 保留原始异常。
- **空库示例数据被误标「实时」**：`hydrate` 无租户分支返回后仍落入成功回调，把内置示例数组升级为「实时」并提示已接入。空库分支加短路，维持「示例」标注与「API 可达 · 暂无租户」。
- **live-smoke 回归守卫**：新增静态断言（本地 `toast(` 包装、禁 `window.toast` 调用、`err.network` 标记、空库 `empty` 短路），防止错误归因/示例误标复发。

### Known limits（v0.0.2 边界）

- 生产 OIDC（ENH-07）、真实暗网 feed（G8-03）、对外通报通道（G8-02）、复测微 VM 池（ENH-10）仍未交付；评分权重/阈值待 G8-01 定稿（`EASM_SCORE_WEIGHTS`/`EASM_SCORE_THRESHOLDS` 仅换配置，不代签）。

## [v0.0.1] - 2026-10-18

首个公开版本（MVP 形态，内存/PG 双后端）。

### Added

- **五阶段巡检工作流**（P1 搜索引擎 / P2 空间测绘 / P3 端口目录 / P4 第三方渠道 / P5 暗网兜底），口径唯一（4/4/5/3/4 步骤）。
- **台账与闭环**：`L-*` 台账唯一事实源；零误报三重门（V-5 双信源 ≥2 / V-10 反证必答 / S-2 复测证据闭环）；四态状态机。
- **处置与通报**：处置工单五态（待整改→处置中→已通报平台→已下架→已处置，跳步/回退/终态锁定 422）；线索通报（公安 24h / 省通报中心 48h，回执才置已报送，A-08 超时显著标识）。
- **暗网线索包**（WP-M2-02）：样本巡检 → 四类指纹归属判定 → 量级区间估算 → 交易链路聚类 → 线索包固化（哈希/时间戳/来源/截图四要素 + 整包 sha256）。
- **报告中心**（WP-M2-09）：按客户/周期/受众（exec/ops/compliance/redteam）/章节参数化实时聚合生成，四受众执行摘要话术差异化；Markdown / JSON 导出；参数组合历史记录。
- **合规报送总结**（FR-LGR-008）：三段结构 + 内容哈希，可导出。
- **console 前端**：零依赖纯静态（`console/`），`easm-live.js` 接入真实端点，视图实时拉取，能力边界经 livebar 标注、不静默降级。
- **授权总闸**：有效期/时间窗/范围校验，无有效授权一票否决并落审计（`no_valid_scope`）。
- **审计**：audit allow/deny 全量仅追加落 PG。
- **CI**：`.github/workflows/ci.yml`（go vet / build / test + C-1 追溯对账 + golangci-lint）。

### Security

- 代码内不含真实凭据：数据库口令/本地用户名以掩码占位（`easm-***`、`<admin-user>`）呈现，真实值由部署环境注入。
- dev 静态令牌（`tok-admin` 等）仅本地演示；生产环境禁用（`EASM_ENV=production` 拒绝加载）。

### Known limits（v0.0.1 边界）

- 生产 OIDC 未接入（ENH-07）；真实暗网 feed 软阻塞（G8-03，模拟 fixture 兜底）；报告 PDF 为遗留能力（本期 md/json）；对外通报通道（G8-02）未触达，以回执录入为「已报送」唯一路径。
