# EASM AI-Native 管理平台 · 第一性原理架构优化方案（监管单位单用户版）

> **文档编号**：EASM-ARCH-OPT-v1.1  
> **日期**：2026-10-19  
> **基线**：2026-10-20 本地工作树（v0.0.2）；文中内部提交号（如 739e6f2）属内部历史追溯，公开仓库以 v0.0.2 为基线。  
> **性质**：架构决策建议书 / 监管单位单用户版 / 12 个月演进蓝图  
> **适用对象**：项目负责人、架构师、后端/前端/测试负责人、安全运营负责人  
> **版本**：v1.1（2026-10-19 更新：单用户 / 监管单位模式）  
> **上位依据**：《总体设计方案》《PRD》《SRS》《详细开发计划》《批判性审查报告》及仓库现状代码

---

## 目录

- [0. 执行摘要](#0-执行摘要)
- [1. 第一性原理：EASM 到底在解决什么问题](#1-第一性原理easm-到底在解决什么问题)
- [2. 现状体检：证据、成熟度与债务](#2-现状体检证据成熟度与债务)
- [3. 根因分析：为什么会长成现在这样](#3-根因分析为什么会长成现在这样)
- [4. 目标架构 v2：EASM Operating System](#4-目标架构-v2easm-operating-system)
- [5. 业务流重构：双节奏运营环](#5-业务流重构双节奏运营环)
- [6. 阶段功能设计：从可交付到可运营](#6-阶段功能设计从可交付到可运营)
- [7. 迁移策略：从当前状态到目标架构](#7-迁移策略从当前状态到目标架构)
- [8. 关键决策记录（ADR）](#8-关键决策记录adr)
- [9. 风险与反脆弱](#9-风险与反脆弱)
- [10. 验收与度量](#10-验收与度量)
- [11. 监管单位单用户模式专项设计](#11-监管单位单用户模式专项设计)
- [附录 A：现状量化证据](#附录-a现状量化证据)
- [附录 B：目标 API 面（建议）](#附录-b目标-api-面建议)
- [附录 C：核心表 DDL 草图](#附录-c核心表-ddl-草图)
- [附录 D：Phase 0 任务清单（可执行）](#附录-dphase-0-任务清单可执行)
- [附录 E：术语表](#附录-e术语表)
- [附录 F：与现有需求/增强项的映射](#附录-f与现有需求增强项的映射)

---

## v1.1 变更摘要（2026-10-19）

本版根据新的使用形态更新：**平台从「甲方企业自用」收敛为「监管单位单用户」**。这不是把 v1.0 的多用户方案简单删掉，而是换一套安全补偿机制。

| # | 变更 | v1.0 | v1.1 |
| --- | --- | --- | --- |
| 1 | 使用形态 | 企业安全团队多角色 | 监管单位一名操作员 |
| 2 | 权限 | 多用户 RBAC + 审批分离 | 单 operator + 能力开关 + 重认证/双通道确认 + 审计 |
| 3 | 数据域 | 单产品租户 + 组织范围 | 单平台 + 多个被监管单位（entity_id）数据域 |
| 4 | 业务流 | 企业自身攻击面闭环 | 辖区组合管理 + 周期评估 + 通报/整改跟踪 + 报送 |
| 5 | 安全补偿 | 双人审批/职责分离 | 重认证 + 双通道 + 冷却期 + break-glass + 审计链 |
| 6 | 路线图 | Phase 3 企业运营 | Phase 3 监管运营与外部协同 |

**保留不变的架构内核**：资产身份 + 观察流 + 暴露图 + Finding/Case + Outbox/Job + AI 五闸 + 证据 WORM + 三重门。  
**明确放弃的**：多用户 RBAC 矩阵、用户/角色管理、SCIM、双人审批。  
**必须补上的**：单用户安全补偿、被监管单位数据域、辖区组合视图、监管报送与整改跟踪。

**Phase 1 实施进展（2026-10-19）**：已落地资产身份/观察流（inventory，规范资产+别名+append-only 观察）、Finding 生命周期（confirmed 必须有证据、closed 必须已确认）、Job Queue（PG SKIP LOCKED 租约、幂等键、重试/死信）、Connector 框架（seed / ct；Observation.Finding 可产出 Finding）与 discovery worker；迁移 025–027；12 个 API 端点；seed -> observation -> asset -> graph 端到端与 app-role PG 集成通过。Phase 2 已接续：资产状态机、DNS/ASM Connector、Finding->ledger 投影、前端资产/发现视图、告警；cloud Connector/告警通知通道仍待。

**Phase 3 实施进展（2026-10-19）**：已落地 Finding 告警通知通道（映射到既有 notify 三闸门）、Finding 批量 confirm/close/project、资产自动衰减（jobworker 周期 + HTTP 手工触发）、cloud/第三方 Connector（通用 feed 契约）、前端筛选/分页/投影台账/告警推送/报告中心入口；新增 3 个 API 端点；go build/go vet/go test（含 app-role PG 集成）/trace-check 通过。仍待：通知模板与重试策略、批量操作审计汇总、衰减策略按资产类型分级、云厂商原生 API、报表按 Finding 维度聚合。

**Phase 2 实施进展（2026-10-19）**：已落地 DNS / ASM Connector（DNS 写 resolves_to 边）、Finding 自动生成（复用 22 条判敏规则）、Finding→ledger 投影（confirmed/verified，严重级仍走门1/门2）、资产状态机、Finding 告警（open/ack）、前端资产/发现/告警实时表；迁移 028–029；新增 4 个 API 端点；go build/go vet/go test（含 app-role PG 集成）/trace-check 通过。Phase 3 已接续：告警通知通道、Finding 批量运营、前端分页/筛选、资产自动衰减、cloud Connector；ASM 厂商字段映射/云厂商原生 API 仍待。

**Phase 0 实施进展（2026-10-19）**：第一批已保存 WIP patch、回滚到绿色基线并实现单用户/实体域：/v1/entities 别名、EASM_SINGLE_USER=1、confirmations 表/端点、regulated_entities 视图（023）、024 迁移。第二批已落地：internal/config 集中装载校验；internal/app.Deps 组装根；cmd/migrate + schema_migrations 迁移工具；OpenAPI 生成/覆盖校验；CI 四门禁；OIDC（RS256/JWKS）、break-glass、passkey（ES256 challenge-response）。go build/go vet/go test（含 app-role PG 集成）/trace-check/live-smoke 全绿。仍待：完整 WebAuthn（passkey 当前为 ES256 step-up）、生产 IdP 联调、前端确认/step-up 面板、config 的少量历史 env 收尾。

> 读法：v1.1 不是「降级为单机玩具」，而是把安全重心从「多人分权」移到「单人多重确认 + 全量审计 + 数据域隔离」。单用户模式最大的风险不是效率，而是「一个人既执行又确认」；必须用制度与技术双重补偿。

---

## 0. 执行摘要

### 0.1 一句话判断

**在监管单位单用户的使用形态下，平台的目标不是服务一个企业的安全团队，而是让一名监管人员持续掌握辖区内多家被监管单位的攻击面，完成「发现—评估—通报—整改—复测—报送」的监管闭环。**

当前系统已经具备一个可信的「治理外壳」（证据、台账、工单、通报、报告、审计），但还没有长成一个真正的 EASM 平台：它的重心仍是「监管五阶段排查项目」，而不是「持续运行的互联网攻击面管理」；AI 仍是旁路能力，不是系统内核；数据模型仍是单单位台账，而不是「辖区 + 多被监管单位 + 实体身份 + 暴露图」。

这不是否定已有工作。项目在「不造假」这件事上做得比多数安全平台更扎实：WORM 证据、零误报三重门、状态机、fail-loud、501 诚实边界、变异测试、追溯对账，这些是应该被保留并放大的**信任内核**。问题在于：**信任内核很硬，发现内核很薄，监管运营内核还没成形。**

### 0.2 工程基线：Phase 0 已恢复绿色（历史红色记录）

在 Phase 0 之前，工作树曾处于一次未收口的单用户化改造中途。执行 **go build -gcflags=-e ./...**（关闭每包错误数截断）曾得到：

- **161 个编译错误，分布在 33 个文件**（默认 go build 每包截断到 10 条，因此直接跑 go build 只会看到 22 条）；
- 集中在 **internal/httpapi**（98 个）与 **internal/pgstore**（63 个）；
- 典型错误：服务层已经去掉 tenant 参数，但 handler/store 仍按多租户签名调用；**s.tenants** 字段已删除但仍有 31 处引用；**internal/tenant** 包已删除但 server_test 仍导入；**pgstore.withTenant** 已删除但 19 处仍在调用。

同时存在四方口径漂移：

| 层 | 当前事实 | 证据 |
| --- | --- | --- |
| Go 领域层 | 保留 tenant 字段作为 entity legacy；单用户/实体域在装配、鉴权、API 与视图层收敛 | 当前实现 |
| HTTP / PG 层 | tenant 路由保留为 legacy，/v1/entities 为一等别名；schema 仍 tenant_id/RLS（即 entity 数据域） | httpapi、pgstore、migrations |
| 前端 | 已切 /v1/entities；顶栏标签改「被监管单位」 | console/easm-live.js、index.html |
| 文档 | 方向已更新；历史多租户/RLS 描述逐步同步 | AGENTS.md、README.md、本方案 |

**Phase 0 已将该基线恢复到绿色**：当前 go build ./... 与 go test ./... -count=1 均通过；并增量落地了 /v1/entities 别名、EASM_SINGLE_USER=1、confirmations 表/端点、迁移 023（entity 视图）与 024（确认表）。**但仍存在语义漂移**：数据库仍用 tenant_id/RLS 作为 entity legacy，前端/文档仍有历史多租户描述；这些在 Phase 0/1 继续同步。

### 0.3 五个结构性调整（本方案的核心主张）

| # | 调整 | 从 | 到 | 为什么 |
| --- | --- | --- | --- | --- |
| 1 | **业务主干换轴** | 五阶段线性排查流水线 | 持续 EASM 运营环 + 合规战役模板 | 五阶段是监管交付方法论，不是 EASM 产品内核；把模板当主干会导致「有治理、无发现」 |
| 2 | **数据模型换心** | 扁平资产清单 + 台账 | 实体身份 + 观察流 + 暴露图 + 发现/处置事件 | 资产会变、会合并、会消失；风险在关系上，不在孤立行上 |
| 3 | **使用形态换位** | 多用户企业自用 / 或一刀切成单机单管理员 | **单用户监管台 + 被监管单位数据域 + 高危动作二次确认** | 监管单位一名操作员；单用户不等于单安全层；用重认证/双通道/冷却期/审计补偿职责分离 |
| 4 | **AI 定位换层** | Provider 旁路（判敏、文案） | 受约束的 Agent 运行时 + 单用户的「第二双眼睛」 | AI-native 不是「加一个模型接口」，而是让 AI 进入每个运营决策点且可控可证 |
| 5 | **工程演进换法** | big-bang 删租户/删 RLS/删角色 | strangler + 兼容层 + 编译/契约/集成三门禁 | 历史 161 个编译错误就是 big-bang 的直接代价；架构演进必须可回滚、可验证 |

### 0.4 12 个月目标（建议对外承诺的口径）

| 维度 | 指标 | 12 个月目标 |
| --- | --- | --- |
| 监管覆盖 | 辖区被监管单位纳管率 | ≥ 95% |
| 评估 | 周期评估完成率 | 100% |
| 发现 | 新增暴露面从出现到入账的 P95 | ≤ 24 小时（持续监测）；≤ 5 分钟（事件触发） |
| 质量 | 严重级结论验证覆盖率 / 误报率 | 100% / ≤ 5% |
| 通报 | 公安 24h / 通报中心 48h 及时率 | 100% |
| 整改 | 高危发现 MTTR / 整改闭环率 | ≤ 7 天（P95） / ≥ 90% |
| 报送 | 报送材料一次通过率 | ≥ 95% |
| AI 质量 | AI 建议采纳率 / 证据引用率 / 幻觉率 | ≥ 60% / 100% / ≤ 2% |
| 运营可用性 | 核心 API 可用性 / P95 延迟 | ≥ 99.9% / ≤ 300ms（读） |
| 审计合规 | 高危动作确认覆盖率 / 审计可回溯率 | 100% / 100% |

> 这些指标按「被监管单位」单列，同时提供辖区聚合视图。监管单位的核心不是「扫得多」，而是「辖区看得全、评估做得完、通报发得及、整改盯得住、材料交得出」。

### 0.5 需要项目负责人拍板的三个决策

1. **单用户安全形态**：是否采用「单 operator + passkey/OTP 重认证 + 双通道确认 + break-glass」？本方案建议是。单用户无法实现真正的双人审批，必须用「可追溯的自我确认」替代；是否保留只读审计导出令牌（建议保留离线导出，不建第二登录账号）？
2. **被监管单位数据域**：是否采用 regulated_entities + entity_id + RLS 的数据域模型？本方案建议是。单用户可以切换单位，但资产、发现、报告、导出必须带 entity_id；是否允许跨单位聚合（建议允许，但必须显式选择并留痕）？
3. **AI 首批场景**：建议先做「只读调查 + 研判/优先级 + 报告草稿」，不做自动扫描、不做自动通报、不做自动闭环。AI 作为单用户的「第二双眼睛」，可以在高危动作前提出反方问题，但不能替代确认。

---

## 1. 第一性原理：EASM 到底在解决什么问题

### 1.1 从场景出发，而不是从功能清单出发

剥离「五阶段」「34 项敏感数据」「22 条规则」「报告模板」这些交付形态，EASM 的第一性问题可以写成一句话：

> **在明确授权的外部视角下，持续回答：我们有哪些暴露面？它们是否真实、是否可达、是否可利用、是否重要？谁在负责？是否已经修好？**

这句话包含六个不可回避的子问题，每个子问题决定一条架构约束：

| 子问题 | 第一性推论 | 架构约束 |
| --- | --- | --- |
| 「我们有哪些」由什么定义？ | 不是一次性清单，而是**实体身份 + 关系 + 时间** | 资产必须有规范身份、别名、首次/末次发现、来源与置信度 |
| 「外部视角」如何获得？ | 必须依赖外部数据源与主动探测，且受授权约束 | 发现能力是平台的一等能力，不是未来插件 |
| 「是否真实」如何证明？ | 单一来源不可信，必须交叉、反证、复现 | 证据链 + 三重门 + 可复测 |
| 「是否可达/可利用」如何表达？ | 风险在实体之间的关系上，而不在孤立节点上 | 暴露图是一等事实源，不是展示层 |
| 「谁负责、是否修好」如何闭环？ | 必须落到人、时限、状态机、复测 | 处置 Case + 确认 + 验证，不以「填表」代替闭环 |
| 「如何持续」？ | 发现、变更、新威胁都会持续发生 | 调度、事件、增量、幂等、可重放 |

### 1.2 十条不可让渡的架构不变量

以下不变量是本方案判断「什么是好架构」的标尺。任何设计决策、代码评审、验收，都应能落到其中一条。

| # | 不变量 | 判据 | 当前状态 |
| --- | --- | --- | --- |
| I-1 | **实体身份唯一** | 同一域名/IP/URL/凭据/组件在任意来源、任意时间只对应一个规范实体；别名可追溯 | 部分：graph 有指纹，asset 仍是扁平 ID |
| I-2 | **观察与当前态分离** | 原始观察 append-only；当前态是可重建投影；支持时间旅行 | 缺失：asset 直接覆盖，无 observation 表 |
| I-3 | **风险在边上** | 任一风险结论可由图上的路径/边解释；孤立节点不产生高危结论 | 部分：13 类实体/11 类关系已定义，但只有 2 类边有写入方 |
| I-4 | **发现确定性、判断可解释** | 发现来自工具/规则的可复现输出；AI 不直接生产事实 | 较好：classify/collect 确定性；AI 不入台账 |
| I-5 | **结论可验证、可证伪** | 严重级必须有交叉信源、反证回答、复测证据 | 较好：三重门已落代码；但验证器仍是过渡形态 |
| I-6 | **闭环以复测为准** | 没有证据的「已修复」不得闭环；复发可重新打开 | 较好：ledger.Verify；但 Finding 生命周期缺失 |
| I-7 | **高危动作确认** | 主动扫描/爆破/对外通报/批量导出必须二次确认；单用户模式下确认必须可追溯 | **缺失**：单用户确认/重认证/双通道尚未落地 |
| I-8 | **一切可审计** | 高危动作、AI 工具调用、确认、数据导出全量 append-only；可关联到人/时间/证据 | 较好：audit + MCP 审计；缺 AI 轨迹与确认链 |
| I-9 | **范围即授权** | 授权范围是一等对象；执行前强制校验；越界拒绝并留痕 | 较好：authz.Scope；但只支持单份全局 scope |
| I-10 | **可运营** | 幂等、可重试、可观测、可备份、可恢复、成本可控 | **弱**：无队列、无 SLO、无优雅停机、无迁移版本表 |

### 1.3 「AI-native」的正确定义

AI-native 不是「在页面上加一个聊天框」，也不是「让模型直接下结论」。本方案给一个可检验的定义：

> **AI-native = AI 参与每一个运营决策点，但每个决策点都必须通过五道闸：工具可调用、证据可引用、评测可放量、确认可拦截、成本可计量。**

五道闸的具体含义：

| 闸 | 要求 | 反模式 |
| --- | --- | --- |
| 工具闸 | AI 只能通过受控 Tool Gateway 访问平台能力；工具分级、输入输出 schema、速率与范围受限 | 模型直连数据库/扫描器；自由拼接 shell |
| 证据闸 | 每个结论必须绑定 evidence_ref/asset_id/finding_id；无证据只能输出「待核查」 | 凭训练记忆回答；编造 CVE/路径 |
| 评测闸 | 新模型/新 Prompt/新工具上线前必须通过评测集与阈值；灰度放量 | 直接全量切换；无基线 |
| 确认闸 | dangerous 工具与对外动作必须人工确认；AI 不能自批 | 自动扫描/自动通报/自动闭环 |
| 成本闸 | 按 entity/案件/功能计量 token、工具时长、扫描配额；超预算可降级/阻断 | 无上限调用；成本不可见 |

AI 的四种正确角色：

1. **归一/富化**：把非结构化数据变成结构化候选（文档分类、截图判敏、实体抽取）。
2. **研判/排序**：解释、关联、去噪、优先级建议（不改变事实）。
3. **调查/编排**：在案件内规划下一步、调用只读工具、汇总证据（可中断、可回放）。
4. **处置/报告**：生成修复建议、工单草稿、报告叙事（人审后生效）。

AI 明确不做的事：

- 不直接创建「已确认」的 Finding；
- 不直接改变资产/发现/工单状态；
- 不直接执行主动扫描、爆破、对外通报；
- 不在无证据时给出确定性结论；
- 不读取超出当前案件/授权范围的数据。

### 1.4 「监管单位单用户」的架构含义

「监管单位单用户」常被误解为「单机、单账号、不要权限、不要审计」。正确的推论是：

| 维度 | 正确含义 | 错误含义 |
| --- | --- | --- |
| 用户 | 一名监管操作员主账号；可用 passkey/OTP 重认证 | 所以不需要审计/确认 |
| 数据 | 辖区多家被监管单位；entity_id 数据域 | 所以所有单位数据混在一起 |
| 权限 | 单用户不需要 RBAC 矩阵；需要能力开关 + 重认证 + 审计 | 所以可以无限制执行高危动作 |
| 部署 | 内网/离线/数据不出域 | 所以可以随意上云 |
| 集成 | 报送通道、邮件、文件交换、ITSM | 所以只做 CSV |
| 模型 | 私有化/可替换/可审计 | 所以绑定某一家云模型 |

**单用户无法实现真正的职责分离。** 这是必须承认的制度事实，不能用「一个账号也能审批」来掩盖。可用的技术补偿是：

1. **重认证**：高危动作前要求 passkey/OTP/密码再次验证；
2. **双通道确认**：对外通报同时通过两个通道（如 passkey + 邮件/OTP）确认；
3. **冷却期**：破坏性动作（删除、批量下架、对外通报）设置 60 秒可取消窗口；
4. **干跑与范围预览**：执行前展示目标、端口、速率、影响面；
5. **强制理由**：输入原因并记录 before/after 快照；
6. **审计链**：append-only + 哈希链 + 定期锚定；
7. **break-glass**：离线恢复码/备用凭据，使用即告警并审计；
8. **可选只读导出令牌**：给审计/领导导出材料，不建立第二个登录账号。

> 制度上必须写明：单人模式是「可追溯的自我确认」，不是「双人复核」。如果监管流程要求双人复核，应在制度层增加外部会签，而不是假装系统里有第二个人。

## 2. 现状体检：证据、成熟度与债务

### 2.1 工程基线：红色，且是「四方漂移」型红色

| 检查项 | 结果 | 证据 |
| --- | --- | --- |
| go build -gcflags=-e ./... | **通过（Phase 0 恢复）** | 历史 161 errors / 33 files；当前 0 |
| go test ./... | **通过** | 全包单测 + 集成 skip 路径通过 |
| 领域层单用户化 | 已改（Asset/Ledger/Sweep/Workorder/Notice/Report 去 Tenant） | 工作树 diff |
| PG 层 | 仍按 tenant 列/withTenant 写 | pgstore/*.go |
| Schema | 仍为 tenant_id + RLS + tenants 表 | migrations/001、003、004 等 |
| 前端 | 仍请求 /v1/tenants/{id}/... | console/easm-live.js 第 119、125、393 行等 |
| 角色 | R1–R8 全部映射为 admin；单用户模式下可接受，但缺重认证/确认/break-glass | internal/rbac/rbac.go |
| 文档 | 仍描述多租户、RLS、55 项租户级端点 | AGENTS.md、README.md |
| CI | 只跑 vet/build/test/trace/lint；当前必红 | .github/workflows/ci.yml |

这不是「某个函数写错」，而是**一次没有兼容层、没有迁移脚本、没有测试同步的跨层大爆炸改造**。Phase 0 的纠偏方式是：保存 WIP patch、回滚到绿色基线、再用增量/别名/迁移实现同一目标（见 §7）。

### 2.2 EASM 能力成熟度盘点

评分口径：0 = 缺失；1 = 有骨架/演示；2 = 可用但有明显缺口；3 = 生产可用；4 = 领先。

| 能力域 | 现状 | 证据 | EASM 要求 | 评分 | 优先级 |
| --- | --- | --- | --- | --- | --- |
| 授权与范围 | 单份全局 Scope，有效期/时间窗/端口/排除/限速/二次授权 | internal/authz | 多授权单、按被监管单位/战役/目标、确认链、执行令牌 | 2 | P0 |
| 辖区组合 | 无；只能单单位视图 | 无 | 多被监管单位档案、组合视图、跨单位对比 | 0 | P0 |
| 资产发现 | 手工建资产；collect 只支持 repo/port/dir 三渠道；sweep 只对已有资产跑规则 | collect、sweep.run | 域名/证书/ASN/云/代码/文档/暗网持续发现 | 1 | P0 |
| 资产身份 | 扁平 Asset，ID 即主键；无别名、首末次、来源、置信度、合并 | internal/asset | 规范实体 + 别名 + 观察流 + 合并/拆分 | 1 | P0 |
| 暴露图 | 13 类实体/11 类关系已定义；只有 resolves_to 与 leaks 两类边有写入方 | graph、ingest、secret | 全关系写入、路径、可达、时间、provenance | 1.5 | P0 |
| 检测 | 22 条判敏规则；gitleaks/nmap/ffuf；暗网样本 | classify、collect、darkweb | 可编排的多工具检测、模板/版本、覆盖率 | 2 | P1 |
| 验证 | 门1/门2/门3；manual/cross_tool/local verifier | ledger、verifier | 安全 PoC、沙箱、回连、证据包 | 2 | P1 |
| 风险评分 | 四因子确定性核；权重/阈值可配；但输入数据不足 | scoring | 图输入完整、业务上下文、控制覆盖、校准 | 1.5 | P1 |
| 处置闭环 | ledger 四态、workorder 五态、notice 回执 | ledger/workorder/notice | Finding 生命周期、SLA、例外/接受、通报/整改跟踪、复发 | 2 | P1 |
| 报告与通报 | 四受众报告、md/json/pdf、线索包、证据链 | report/notice | 模板化、辖区对比、审计、真实通道、时效 | 2.5 | P2 |
| 持续监测 | 进程内 tick + asset diff + 任务单；无持久调度 | monitor | 持久调度、事件驱动、增量、变更检测 | 1 | P1 |
| AI | mm 判敏、shadow 文案、evalset 骨架；无 Agent 运行时 | ai/mm/shadowit/evalset | Agent、工具、证据 RAG、评测、确认、成本 | 1 | P2 |
| 身份与权限 | 单 admin + confirmations（可选强制）；缺 OIDC/重认证/break-glass | rbac、httpapi.confirm | 单用户 OIDC/Passkey、重认证、双通道、审计链 | 1.5 | P0 |
| 可观测/运维 | 仅 ReadHeaderTimeout；无 metrics/trace/优雅停机/迁移版本 | cmd/server、Makefile | SLO、trace、指标、备份恢复、迁移工具 | 0.5 | P0 |
| 前端 | 260KB app.js + 56KB live 层 + 静态 HTML；演示数据与真实数据双路径 | console | 模块化、类型化、单一数据源、性能预算 | 1 | P2 |

> 读法：**评分 1 的项不是「以后再说」，而是「不补就无法称为 EASM」**。尤其是资产发现、资产身份、辖区组合、持续监测、身份权限五项。

### 2.3 十个架构债务（按影响排序）

| # | 债务 | 影响 | 证据 |
| --- | --- | --- | --- |
| D-1 | 跨层 big-bang 改造未收口 | 已收口（Phase 0 恢复绿色）；剩余 schema/文档语义同步 | 历史 161 build errors；当前 0 |
| D-2 | 内存/PG 双后端 + 显式列手写 | 双后端行为漂移、字段丢失、测试掩盖 | pgstore/ledger.go 等 |
| D-3 | 组装根 27 个参数 + 28 个 env 散落 | 已收口：internal/config + internal/app.Deps；少量历史 env 待清 | config、app、cmd/server |
| D-4 | 无领域事件/事务边界 | 跨域一致性靠手工补偿；无法重放/审计 | asset→graph 补偿回滚是孤例 |
| D-5 | 进程内状态/定时器 | 重启丢状态；无法水平扩展；调度不可观测 | monitor.Start、sweep 内存 map |
| D-6 | 图谱写入面极窄 | Top5/路径/评分在真实数据下没有输入 | 仅 resolves_to + leaks |
| D-7 | 插件契约是「元数据」而非「执行契约」 | 工具专有解析留在平台，AX-6 名存实亡 | collect/parse_*.go |
| D-8 | 93 条路由无 OpenAPI/错误目录 | 已生成 110 路由 OpenAPI 骨架并纳入 CI；完整 schema/错误目录待补 | docs/api/openapi.json、scripts/openapi-check.py |
| D-9 | 无 SLO/指标/链路追踪 | 出了问题只能看日志；无法证明「首屏 3 秒」 | cmd/server、httpapi |
| D-10 | 文档/代码/前端/schema 四方漂移 | 已同步主要方向；历史多租户段落仍待清 | AGENTS/README vs code |

### 2.4 必须保留的「信任内核」

以下能力是项目的差异化资产，不应在重构中丢失：

1. **证据先行**：evidence.Store WORM、raw_ref/snapshot_ref、哈希锚定、PDF 确定性导出。
2. **零误报三重门**：门1 双信源、门2 反证必答、门3 复测证据；且所有入账路径共用闸门，旁路无门。
3. **状态机与不可虚报闭环**：ledger 四态、workorder 五态、notice 三要素锁定、回执才置已报送。
4. **fail-loud 装配**：env 设置但装载失败一律 fatal；可选能力未装配返回 501 + code，不返回空数据。
5. **测试纪律**：TDD、变异验证、双后端契约测试、live-smoke 双向守卫、trace-check。
6. **确定性报告**：同报告同字节、字体子集化、可独立复核的内容哈希。

**优化原则：把新能力长在这个信任内核上，而不是推倒它。**

---

## 3. 根因分析：为什么会长成现在这样

### 3.1 根因 R1：把「监管排查项目」当成了「EASM 产品」

**表现**：系统的主对象是「五阶段」，主流程是「建资产 → 跑规则 → 入台账 → 发工单/通报 → 出报告」。sweep 的 P1–P5 并不是真正的发现流程，而是对已有资产反复跑判敏规则的循环。

**证据**：internal/sweep/sweep.go 的 run() 中，每个阶段的每个步骤都对同一批 assets 调用 classify.Detect；P1/P2 没有任何搜索引擎/空间测绘/证书发现动作；注释也承认「ENH-08 工具链接入后替换为采集+判定」。

**后果**：
- 没有资产发现，平台就只能治理「人喂进来的资产」；
- 五阶段的步骤数（4/4/5/3/4）变成了验收口径，而不是能力口径；
- 客户看到的是「排查工作流」，不是「攻击面管理」。

**纠正**：五阶段降为「合规战役模板」，主干改为持续 EASM 运营环（§5）。P1–P5 作为**渠道/证据要求**的映射保留，但不作为系统的主状态机。

### 3.2 根因 R2：把「单用户」误读为「单安全层」

**表现**：为了「监管单位单用户、不要多账号」，一次性删除 tenants、RLS、InScope、R1–R8，把角色全部映射为 admin。

**这里混了三件事**：

1. **产品多租户**：一个平台服务多个客户 —— 单用户监管平台确实不需要；
2. **被监管单位数据域**：一个平台管理辖区多家单位 —— **必须有**，否则报表、导出、通报会串域；
3. **高危动作确认**：谁执行、谁确认、谁留痕 —— **必须有**，否则单账号可以无确认扫描、通报、删除。

单用户是产品决策，不是安全模型。当前改造把三者一起删掉，等于「去掉 SaaS 多客户」的同时，也去掉了「辖区数据分区」与「动作确认」。

**后果**：
- 辖区多家被监管单位的资产、发现、报告无法可靠分区；
- 单账号可以无二次确认执行主动扫描、对外通报、批量导出；
- 审计只能回答「操作员做了什么」，无法可靠回答「对哪个单位做了什么」；
- 未来想加只读审计/领导视图，又要跨层大改。

**纠正**：
- **单 operator**：不建用户/角色矩阵，但保留能力开关；
- **entity_id 数据域**：所有业务表带被监管单位 ID，RLS 按 entity 隔离；
- **Confirmation**：高危动作前重认证 + 理由 + 范围哈希 + 冷却期；
- **审计链**：actor + session + entity + action + before/after hash。

一句话：**去掉的是多用户和多租户 SaaS，不是数据域与动作确认。**

### 3.3 根因 R3：以「台账」为中心，而不是以「实体 + 观察 + 发现 + 处置」为中心

**表现**：ledger.Item 同时承担「发现事实、合规字段、处置状态、复测记录、通报触发」五种职责；资产只有一张扁平表；没有 observation、没有 finding、没有 case。

**后果**：
- 发现的生命周期被合规字段绑架（phase/category/action/due/owner 必填），非合规场景无法表达；
- 同一实体多次发现无法保留历史；资产消失/变更无法回溯；
- 处置、复测、通报都挂在 ledger 上，任何新流程都要改 ledger；
- 报告只能从台账聚合，无法从「攻击面变化」讲故事。

**纠正**：引入四层模型（§4.4）：
- **Observation**：原始观察，append-only；
- **Asset**：规范实体当前态，由观察投影；
- **Finding**：可验证的暴露结论，独立生命周期；
- **Case/Remediation**：处置与复测；
- **LedgerEntry**：合规投影，从 Finding + Campaign 映射生成，保留兼容 API。

### 3.4 根因 R4：把「发现能力」外置为未来插件

**表现**：平台把 P1/P2/P4 的真实发现都推给 ENH-08/ENH-10，当前只做判定与入账。

**后果**：
- 平台没有自己的「眼睛」，只能等人工导入或单点 CLI；
- 插件契约只有元数据（id/cmd/cap/risk/auth），没有输入输出 schema、版本、健康检查、fixture、签名；
- 工具专有解析留在平台（collect/parse_*.go），违反 AX-6 的精神：平台仍在随工具变化而改代码。

**纠正**：
- 插件契约升级为「执行契约」（§4.6）：manifest + schema + fixture + health + signature；
- 平台只做编排、归一、校验、存储；工具适配器负责原生输出解析；
- 先接 3 个高价值发现源（CT 日志、DNS/子域、云/ASM API），再扩展。

### 3.5 根因 R5：AI 以 Provider 旁路接入，没有运行时

**表现**：internal/ai 只是一个 Chat 接口；mm 做图片判敏，shadow 做文案；evalset 只评测 classify 规则。没有 Agent 循环、没有工具调用、没有证据 RAG、没有案件记忆、没有 AI 审计。

**后果**：
- 「AI-native」目前是营销词，不是架构事实；
- 即使接入更强的模型，也无法完成「调查一个可疑暴露」这种多步任务；
- 没有评测与审计，放开 AI 动作会直接破坏「不造假」的口碑。

**纠正**：建立 AI Operating Layer：Agent Runtime + Tool Gateway + Context/Evidence + Policy/Confirmation + Eval/Release + Memory + Cost。先只读，再受控，最后确认后动作。

### 3.6 根因 R6：用 big-bang 做架构演进

**表现**：单用户化一次跨领域层、HTTP 层、PG 层、前端、文档、测试同时改；没有兼容层、没有迁移脚本、没有 feature flag。

**后果**：历史上曾产生 161 个编译错误；即使修完，也会留下 schema/前端/文档漂移；回滚成本高。Phase 0 已用「保存 WIP + 回滚 + 增量实现」纠偏。

**纠正**：
- 任何跨层改造必须走 strangler：新接口并行、双写/回放、读路径切换、旧路径下线；
- 每个阶段必须可编译、可测试、可回滚；
- CI 增加「编译 + 契约 + 集成 + 迁移 dry-run」四门禁。

### 3.7 根因 R7：缺少运营架构

**表现**：没有持久调度、没有任务队列、没有 SLO、没有指标/追踪、没有优雅停机、没有迁移版本表；monitor 是进程内 tick，sweep 是同步执行。

**后果**：
- 只能演示，不能 7×24 运营；
- 扫描任务一多就互相拖垮；重启丢任务；
- 出了问题无法定位是「没扫到」还是「没入库」。

**纠正**：补齐执行平面与可观测性（§4.6/§4.9），把「运营」当成一等需求。

---

## 4. 目标架构 v2：EASM Operating System

### 4.1 架构原则

| # | 原则 | 含义 | 反例 |
| --- | --- | --- | --- |
| P-1 | 领域优先 | 按业务能力分界，不按技术分层堆包 | 所有 handler 塞一个 httpapi 包 |
| P-2 | 事件驱动 | 跨域通过领域事件/Outbox 解耦，可重放 | 资产入账后手工调 5 个服务 |
| P-3 | PG 为唯一事实源 | 生产只认真实 PG；内存仅测试 | 生产可静默回退内存 |
| P-4 | 无状态服务 | API/Worker 可水平扩展；状态在 PG/对象存储 | 进程内 map 存任务/告警 |
| P-5 | 幂等优先 | 所有命令/任务有幂等键；至少一次消费 | 重试导致重复入账 |
| P-6 | 证据先行 | 任何结论可回溯到原始产物 | 只存摘要不存原文 |
| P-7 | 策略即代码 | 授权、确认、风险门、AI 工具权限可配置、可测试 | 规则散落在 handler |
| P-8 | AI 有界 | AI 只在工具/证据/评测/确认/成本五闸内行动 | 模型直连扫描器 |
| P-9 | API 优先 | OpenAPI 是契约；前端/CLI/MCP 共用 | 前端手写路径 |
| P-10 | 默认可观测 | 每个请求/任务/Agent 有 trace_id；核心指标可查 | 只打日志 |
| P-11 | 离线友好 | 单机/内网可运行；外部依赖可裁剪 | 强依赖云服务 |
| P-12 | 无聊技术 | 优先 PG/标准库/成熟组件；少造轮子 | 自研分布式队列 |

### 4.2 分层视图

~~~mermaid
flowchart TB
  subgraph L5[L5 体验层]
    WEB[Web Console]
    REST[REST / OpenAPI]
    MCP[MCP Gateway]
    CLI[CLI / 自动化]
  end

  subgraph L4[L4 AI Operating Layer]
    AG[Agent Runtime]
    TG[Tool Gateway]
    CTX[Context & Evidence Binder]
    POL[Policy & Confirmation]
    EVAL[Eval & Release Gate]
    MEM[Case Memory]
    COST[Cost & Usage]
  end

  subgraph L3[L3 领域服务]
    SCOPE[Entity & Scope]
    DISC[Discovery]
    IDENT[Asset Identity & Graph]
    DET[Detection]
    VAL[Validation]
    RISK[Risk & Prioritization]
    REM[Remediation & Verification]
    CAMP[Entity Campaign & Reporting]
    IAM[Operator & Session]
    AUD[Audit]
  end

  subgraph L2[L2 执行平面]
    SCH[Scheduler]
    JOB[Job Queue / Lease]
    WRK[Worker Pool]
    PLG[Scanner Plugin Runtime]
    SBX[Sandbox & Egress]
  end

  subgraph L1[L1 数据平面]
    PG[(PostgreSQL SoR)]
    OBJ[(Object Store WORM)]
    OUT[Transactional Outbox]
    IDX[Optional Search / Graph Provider]
  end

  WEB --> REST
  CLI --> REST
  REST --> SCOPE
  MCP --> TG
  AG --> TG
  AG --> CTX
  AG --> POL
  AG --> EVAL
  AG --> MEM
  AG --> COST
  TG --> DISC
  TG --> DET
  TG --> VAL
  TG --> REM
  DISC --> IDENT
  IDENT --> DET
  DET --> VAL
  VAL --> RISK
  RISK --> REM
  REM --> CAMP
  SCOPE --> JOB
  DISC --> JOB
  DET --> JOB
  VAL --> JOB
  JOB --> WRK
  WRK --> PLG
  PLG --> SBX
  WRK --> PG
  WRK --> OBJ
  PG --> OUT
  OUT --> DISC
  OUT --> DET
  OUT --> CAMP
  IDENT --> PG
  RISK --> PG
  CAMP --> PG
  IAM --> PG
  AUD --> PG
~~~

**关键变化**：
- 五阶段不再是顶层结构；Campaign 只是领域服务之一。
- AI 层与领域层通过 Tool Gateway 交互，不直连数据库/扫描器。
- 执行平面独立：调度、队列、Worker、插件、沙箱。
- 数据平面以 PG 为事实源，Outbox 驱动跨域事件。

### 4.3 限界上下文与职责

| 上下文 | 聚合根 | 主要命令 | 主要事件 | 存储 |
| --- | --- | --- | --- | --- |
| Operator & Session | Operator, Session, APIToken, BreakGlass | login, reauth, rotate token, recover | OperatorAuthenticated, ReauthPerformed, BreakGlassUsed | PG |
| Regulated Entity & Scope | RegulatedEntity, Scope, Authorization, Confirmation | register entity, define scope, confirm action | EntityRegistered, ScopeActivated, ConfirmationGranted | PG |
| Discovery | Source, Seed, ConnectorRun | add seed, run connector, ingest observation | ObservationIngested, SourceFailed | PG + 对象存储 |
| Asset & Graph | Asset, Alias, Relationship | resolve identity, merge, retire | AssetCreated, AssetMerged, AssetRetired | PG |
| Detection | DetectionRule, ScanJob, FindingCandidate | run detector, normalize candidate | FindingCandidateCreated | PG + 对象存储 |
| Validation | Validation, Evidence, Refutation | validate, refute, reproduce | FindingValidated, FindingRefuted | PG + WORM |
| Risk | RiskAssessment, ScoreConfig | score, recalibrate | RiskScored, RiskChanged | PG |
| Remediation | RemediationCase, Action, Verification | assign, remediate, verify, close | CaseOpened, CaseVerified, CaseClosed | PG |
| Campaign & Reporting | Campaign, StageRun, Report, Notice | plan, execute stage, report, notify | CampaignStarted, ReportPublished, NoticeSent | PG + WORM |
| Knowledge | Rule, IntelEntry, VulnEntry, Playbook | import, publish | KnowledgeUpdated | PG |
| AI Operations | AgentRun, ToolCall, PromptVersion, EvalRun | run agent, evaluate, promote | AgentRunCompleted, EvalGatePassed | PG |
| Platform | Job, OutboxEvent, AuditEntry, Config | enqueue, replay, audit | JobFailed, AuditAppended | PG |

**边界规则**：
- 只有 Asset & Graph 可以写资产/关系；
- 只有 Validation 可以把 Finding 置为 confirmed；
- 只有 Remediation 可以置 closed；
- 只有 Campaign & Reporting 可以生成对外材料；
- 只有 Operator & Session 可以执行重认证/break-glass；
- AI Operations 只能产生 suggestion/action request，不能直接写上述状态；
- 所有 dangerous 动作必须携带有效的 Confirmation 记录。

### 4.4 核心数据模型

#### 4.4.1 资产身份：Asset + Alias + Observation

~~~text
Asset
  id                ULID
  entity_id         regulated entity (data domain)
  kind              domain|ip|port|web|cert|cloud|repo|credential|component|person|org|business
  canonical_key     normalized identity (e.g. dom:example.com, ip:1.2.3.4, web:https://...)
  display_name
  state             candidate|confirmed|active|stale|retired
  confidence        0..1
  first_seen, last_seen
  business_system_id, owner_id
  criticality       crown_jewel|high|medium|low|unknown
  in_scope          bool
  sources           [source_id]
  attributes        jsonb (kind-specific)

AssetAlias
  asset_id, alias_key, alias_type, source, first_seen, last_seen

AssetObservation
  id, asset_key, source_id, observed_at, raw_ref, payload_hash, payload jsonb
  -- append-only; current state is a projection
~~~

**为什么必须这样**：
- 同一域名可能来自 CT、DNS、搜索引擎、证书、手工；没有 alias 就会重复；
- 资产会消失又出现；没有 observation 就无法做变更检测与时间旅行；
- 置信度让「疑似影子资产」与「已确认资产」共存而不污染台账。

#### 4.4.2 暴露图：Relationship 带 provenance 与有效期

~~~text
Relationship
  id, entity_id, from_asset_id, to_asset_id, type
  confidence, first_seen, last_seen, valid_from, valid_to
  evidence_ref, source_id, attributes jsonb
  unique(from, to, type, valid_from)
~~~

关系类型至少覆盖：owns、in_scope、resolves_to、cname、behind_cdn、hosts、serves、uses、affects、leaks、valid_on、reachable、depends_on、protects、observed、evidence_of。

**写入规则**：
- 每条边必须有 source + evidence_ref（除人工确认边）；
- 边的时间语义：valid_from/valid_to 支持「曾经可达，现在不可达」；
- 图查询默认只看 valid_to 为空或大于当前的边；
- 合并资产时边要重指向，保留历史。

#### 4.4.3 发现：Finding 与 Ledger 分离

~~~text
Finding
  id, entity_id, asset_id, type, title
  lifecycle         new|triaged|validating|confirmed|remediating|verified|closed|false_positive|risk_accepted|duplicate
  severity          critical|high|medium|low|info
  confidence        0..1
  first_seen, last_seen
  source, rule_id, evidence_refs[]
  risk_assessment_id
  remediation_case_id
  -- 不合规字段；合规字段在 LedgerEntry

LedgerEntry (compliance projection)
  id, entity_id, finding_id, campaign_id
  phase, category, action, owner, due, status
  xchk[], refute[], verifs[]
  -- 保留现有 API 语义；由投影器生成/同步
~~~

**迁移策略**：现有 ledger 表保留为投影；新 Finding 写入时同步生成 LedgerEntry（若命中合规规则）；读路径先双读，后切 Finding。这样既不破坏现有报表，又能让新流程独立演进。

#### 4.4.4 处置：Case + Action + Verification

~~~text
RemediationCase
  id, entity_id, finding_id, owner_id, priority, sla_due
  state             open|assigned|in_progress|pending_verify|verified|closed|reopened
  actions[]         (type, actor, ts, note, evidence_ref)
  verification_id
  risk_acceptance   (reason, confirmation_id, expires_at) -- 例外
~~~

**规则**：
- closed 必须有 verification.result=reproduced + evidence_ref；
- risk_accepted 必须有 confirmation_id + expires_at，到期自动重开；
- 复发（同一 fingerprint 再次出现）自动 reopened，并关联历史。

#### 4.4.5 授权与确认：Scope 与 Confirmation 是一等对象

~~~text
Scope
  id, entity_id, name
  domains[], cidrs[], ports[], excludes[]
  valid_from, valid_to, time_window, rate_limit
  intrusive_allowed, second_auth_required
  document_ref, document_hash, signer
  state draft|active|expired|revoked|suspended

Confirmation
  id, action, resource, entity_id
  operator_id, method (passkey|otp|password), channel
  reason, scope_hash, before_hash
  ts, expires_at, consumed_at
~~~

**规则**：
- 主动扫描必须同时满足：entity scope active + target in scope + confirmation valid + rate limit；
- 侵入性动作（爆破/弱口令/利用）必须重认证 + 短有效期确认；
- 对外通报必须双通道确认（passkey + OTP/邮件），并记录材料哈希；
- 破坏性动作（删除/批量下架）必须有理由 + 冷却期；
- Confirmation 是一次性、短时效的「自我确认」，不是双人审批；
- 监管场景的授权依据可以是检查通知/任务书/合同；同样记录 document_ref、document_hash、signer；
- 所有 Confirmation 全量审计，可按 entity/action/时间检索。

#### 4.4.6 事件与 Outbox

所有跨域状态变化写 outbox：

~~~text
outbox_event
  id, entity_id, aggregate_type, aggregate_id, event_type, payload jsonb,
  occurred_at, published_at, attempts, last_error
  unique(aggregate_type, aggregate_id, event_type, dedupe_key)
~~~

消费者至少一次；用 dedupe_key 幂等；失败进 DLQ；支持按 aggregate/时间重放。

**事件目录（最小集）**：

| 事件 | 生产者 | 消费者 | 用途 |
| --- | --- | --- | --- |
| ObservationIngested | Discovery | Asset & Graph | 归一/合并 |
| AssetCreated/Updated/Merged/Retired | Asset & Graph | Detection, Risk, Campaign | 触发检测/评分/报告 |
| FindingCandidateCreated | Detection | Validation | 进入验证 |
| FindingValidated/Refuted | Validation | Risk, Remediation, Eval | 评分/处置/回流 |
| RiskScored | Risk | Remediation, Campaign | 优先级/SLA |
| CaseOpened/Verified/Closed/Reopened | Remediation | Campaign, Notification | 报告/告警 |
| CampaignStageCompleted | Campaign | Reporting | 进度/报告 |
| ConfirmationGranted/Expired | Operator & Session | Execution | 执行闸 |
| AgentRunCompleted | AI Operations | Audit, Eval | 轨迹/评测 |
| JobFailed | Platform | Ops Alerting | 运维告警 |

### 4.5 执行平面：从「同步函数」到「可运营任务」

#### 4.5.1 任务模型

~~~text
job
  id, entity_id, kind, payload jsonb, priority
  state queued|leased|running|succeeded|failed|dead|canceled
  scope_id, approval_id, requested_by
  idempotency_key unique
  lease_owner, lease_until, heartbeat_at
  attempts, max_attempts, next_run_at
  created_at, started_at, finished_at
  last_error, result_ref
~~~

- **队列**：PG 表 + SELECT ... FOR UPDATE SKIP LOCKED（单机/小规模足够）；规模上来再换 Temporal/Redis，接缝不变。
- **租约**：Worker 领任务写 lease_until + heartbeat；超时自动回收，避免「进程死了任务永远 running」。
- **重试**：指数退避；可重试错误 vs 永久错误分类；超过 max_attempts 进 dead。
- **取消**：用户取消置 canceled；Worker 通过 ctx 感知；已发出的工具调用尽力终止并留痕。
- **幂等**：idempotency_key = hash(kind + target + scope + window + params)；重复提交返回同一 job。
- **配额**：按 scope/tool/tenant 限制并发与速率；超限排队而不是失败。

#### 4.5.2 插件执行契约 v2

现有 plugin 契约只有元数据，建议升级为：

| 字段 | 说明 |
| --- | --- |
| id / version / vendor | 唯一标识与版本 |
| capabilities | 能力码（STR/MAP/SCAN/EXT/DRK + 具体动作） |
| input_schema / output_schema | JSON Schema；平台强校验 |
| risk_level | readonly/controlled/dangerous |
| network_class | passive/active/egress |
| requires_authz / requires_confirmation | 权限/确认联动 |
| command / args_template | 只允许白名单二进制与参数模板 |
| timeout / resources | 超时与资源上限 |
| fixtures | 黄金样例（输入/输出），CI 回归 |
| health_check | 自检命令 |
| signature | 包签名/哈希，防供应链篡改 |

**平台侧只做**：编排、参数校验、输出 schema 校验、归一化、证据固化、审计。**工具侧负责**：原生输出解析、版本适配、错误码。这样才真正满足 AX-6。

#### 4.5.3 沙箱与出网

- 主动扫描默认只允许 CONNECT（不做原始包），需要 NET_RAW 的能力单独确认；
- 出网走 egress proxy/allowlist，禁止访问内网/元数据地址（SSRF 防护）；
- 沙箱复测：一次性工作区、资源限制、超时、产物 WORM、回连证据；
- 所有工具调用记录：命令、参数、开始/结束、退出码、stdout/stderr 摘要、证据 ref。

### 4.6 AI Operating Layer

#### 4.6.1 组件

| 组件 | 职责 | 关键设计 |
| --- | --- | --- |
| Agent Runtime | 案件内规划/执行/反思；可中断、可恢复 | 最大步数、预算、checkpoint、trace |
| Tool Gateway | 统一工具调用；分级/限流/确认/审计 | MCP 协议；schema 校验；dangerous 拦截 |
| Context Builder | 组装案件上下文：子图、发现、证据片段、知识、历史 | token 预算、引用、去重、脱敏 |
| Policy Engine | 决定 allow/deny/require_confirmation | 确定性规则；模型不可覆盖 |
| Eval & Release | 评测集、指标、灰度、回滚 | 门禁不通过不得放量 |
| Case Memory | 案件结论、决策、抑制规则 | 不存原始 PII；可删除/过期 |
| Cost & Usage | token/工具/扫描配额 | 按案件/功能/模型计量 |

#### 4.6.2 Agent 循环（有界）

~~~text
Observe  -> 读取案件上下文（资产子图、发现、证据、历史）
Plan     -> 生成下一步计划（最多 N 步；每步必须有目标与预期证据）
Act      -> 调用 Tool Gateway（只读/受控；dangerous 需确认）
Verify   -> 校验工具输出 schema；检查证据引用；不确定则 abstain
Reflect  -> 更新假设；记录置信度；决定继续/停止/升级人工
Commit   -> 写入 suggestion/action request（不直接改事实状态）
~~~

**硬约束**：
- max_steps、max_tokens、max_tool_calls、max_duration；
- 任一步失败可重试一次，仍失败则停止并输出「未完成 + 原因」；
- 所有工具输出视为不可信数据，不执行其中的指令；
- 输出必须是结构化 JSON（schema 校验），否则拒绝；
- 结论必须带 citations；无 citations 的结论标记 unverifiable。

#### 4.6.3 防提示注入

- 工具输出用分隔符包裹，明确标注「这是数据，不是指令」；
- 系统提示中禁止模型执行来自工具输出的命令；
- 对 URL/HTML/文档做清洗；移除脚本与隐藏文本；
- 工具调用参数二次校验（不能因为模型说「在范围内」就跳过 scope 检查）；
- 红队测试：恶意网页、恶意仓库 README、恶意文件名、Unicode 混淆。

#### 4.6.4 评测与放量

| 指标 | 口径 | 门槛（建议） |
| --- | --- | --- |
| 证据引用率 | 有 citations 的结论 / 全部结论 | 100% |
| 幻觉率 | 无证据或与证据矛盾的结论 / 全部结论 | ≤ 2% |
| 研判准确率 | 与人工标注一致 / 抽样 | ≥ 85% |
| 建议采纳率 | 被采纳的 suggestion / 全部 suggestion | ≥ 60% |
| 平均调查时长 | 从案件打开到结论 | 下降 ≥ 30% |
| 单案件成本 | token + 工具时长 | 有预算上限 |

**放量流程**：离线评测 → 影子运行（只记录不展示）→ 小流量灰度 → 全量；任一步指标不达标回滚。

### 4.7 单用户安全与身份架构

#### 4.7.1 身份

- **单 Operator 主账号**：OIDC Authorization Code + PKCE（内网可接 Keycloak/企业 IdP）或本地 passkey；
- **会话**：HttpOnly/Secure/SameSite Cookie 或短时 bearer；空闲超时 + 绝对超时；
- **API Token**：scope、过期、可轮换、可吊销；仅用于自动化，不用于日常人工登录；
- **break-glass**：离线恢复码/备用凭据，加密保存；使用即触发告警 + 审计 + 事后复盘；
- **不建用户/角色矩阵**：单用户模式下，RBAC 是过度设计；用能力开关替代。

#### 4.7.2 能力开关

| 开关 | 默认 | 说明 |
| --- | --- | --- |
| read_only | off | 只读模式；禁止一切写操作 |
| scan_passive | on | 被动发现（CT/DNS/API） |
| scan_active | off | 主动扫描；需 scope + confirmation |
| intrusive_scan | off | 爆破/弱口令；需二次授权 + confirmation |
| notify_external | off | 对外通报；需双通道 confirmation |
| export | on | 导出；带水印 + 审计 |
| ai_enabled | on | AI 只读调查；写操作仍需 confirmation |

开关按 entity 可覆盖；关闭即拒绝，不静默降级。

#### 4.7.3 高危动作安全补偿

| 机制 | 适用 | 实现 |
| --- | --- | --- |
| 重认证 | 主动扫描、对外通报、删除、批量导出 | passkey/OTP；5 分钟有效 |
| 双通道 | 对外通报、重大报送 | passkey + OTP/邮件；材料哈希 |
| 冷却期 | 删除、批量下架、对外通报 | 60 秒可取消；倒计时可见 |
| 干跑/范围预览 | 扫描、批量操作 | 展示目标/端口/速率/影响面 |
| 强制理由 | 所有 dangerous | 文本 + before/after hash |
| 速率/配额 | 扫描、导出、AI | 按 entity/动作限流 |
| kill switch | 全局 | 一键停止所有任务与 AI |

#### 4.7.4 数据域

- 所有业务表带 **entity_id**；RLS 按 **entity_id** 隔离；
- 查询必须显式带 entity，或显式选择「辖区聚合」；
- 跨 entity 聚合只返回聚合值，不返回可反推单单位的明细（除非显式选择）；
- 导出带 entity 标识、时间、水印、哈希；跨单位导出需二次确认；
- 单用户可以切换 entity，但切换动作写审计。

#### 4.7.5 审计链

- 字段：actor、session、device、IP、entity、action、resource、result、reason、before_hash、after_hash、prev_hash、hash；
- 追加 only；日/周锚定到对象存储；
- 支持按 entity/action/时间/资源检索；
- 保留 ≥ 180 天（建议 1 年）。

#### 4.7.6 连续性

- break-glass 离线保存，双人保管（制度上）；
- 恢复码打印/密封，使用需登记；
- 加密备份 + 恢复演练（每季度）；
- 交接 runbook：账号、凭据、恢复、常用任务；
- 单点风险如实登记：一人休假/离职时的最小可运营方案。

#### 4.7.7 未来如果要加第二个人

不要先上 RBAC。优先顺序：
1. 只读审计导出令牌（不建登录账号）；
2. break-glass 第二凭据；
3. 只读 observer 账号（如确有必要）；
4. 最后才考虑多角色 RBAC。

**Phase 0 实现**：OIDC（RS256/JWKS，`EASM_OIDC_*`）、break-glass（`EASM_BREAKGLASS_HASH`，每次使用写审计）、passkey（ES256 challenge-response，`EASM_PASSKEY_PUBLIC_KEY` + `X-EASM-StepUp`）。完整 WebAuthn（CBOR/COSE/attestation）保留为 Provider 替换，接缝不变。

### 4.8 可观测性与 SLO

| 类别 | 内容 | 工具 |
| --- | --- | --- |
| Metrics | RED（请求）、USE（资源）、业务指标（发现数、验证率、MTTR） | Prometheus/OpenTelemetry |
| Traces | API → Service → Job → Tool → AI 调用 | OpenTelemetry |
| Logs | 结构化 JSON；request_id/trace_id/job_id/agent_run_id | stdout + 采集 |
| Audit | 独立 append-only；不可与业务日志混合 | PG/对象存储 |
| Dashboards | 驾驶舱、任务队列、扫描健康、AI 质量、成本 | Grafana 或内置 |

**SLO 建议**：

| SLI | SLO |
| --- | --- |
| 核心读 API 可用性 | 99.9% |
| 核心读 API P95 | ≤ 300ms |
| 任务排队 P95 | ≤ 60s |
| 发现入库 P95 | ≤ 5min（事件触发） |
| 报告生成 P95 | ≤ 30s |
| 审计写入成功率 | 99.99% |

### 4.9 部署与数据主权

- **形态**：单二进制 server + worker（可合并部署）+ PostgreSQL + 对象存储；可选 Redis/OpenSearch/Neo4j。
- **离线**：所有依赖可离线安装；模型走内网/私有端点；许可证与 SBOM 随包。
- **备份**：PG 全量 + WAL 归档；对象存储版本化；每日校验；每季度恢复演练。
- **迁移**：版本表 + up/down + dry-run；迁移与应用版本绑定；禁止手工 psql 顺序执行（当前 Makefile 方式必须替换）。
- **升级**：蓝绿/滚动；先迁移后切流量；失败回滚脚本。
- **数据保留**：原始证据 ≥ 1 年；审计 ≥ 1 年；AI 轨迹 ≥ 180 天；PII 按策略脱敏/删除。


---

## 5. 业务流重构：双节奏运营环

### 5.1 从「一条五阶段流水线」到「三条节奏」

当前系统只有一条节奏：用户点「开始排查」→ 五阶段顺序执行 → 台账。EASM 需要三条节奏同时存在：

~~~mermaid
flowchart LR
  subgraph C[持续节奏 Continuous]
    C1[持续发现] --> C2[身份归并]
    C2 --> C3[暴露检测]
    C3 --> C4[验证]
    C4 --> C5[评分/分派]
    C5 --> C6[处置/复测]
    C6 --> C7[学习/调优]
    C7 --> C1
  end

  subgraph E[事件节奏 Event]
    E1[新资产/变更] --> E2[增量检测]
    E3[新 CVE/PoC] --> E2
    E4[新泄露/暗网样本] --> E2
    E2 --> C4
  end

  subgraph K[合规战役 Campaign]
    K1[选定范围/模板] --> K2[P1-P5 任务]
    K2 --> K3[证据/台账]
    K3 --> K4[报告/通报]
    K4 --> K5[归档/复盘]
  end

  C2 --> K2
  C4 --> K3
  C6 --> K4
~~~

**三条节奏的关系**：
- **持续节奏**是主干：7×24 跑发现、检测、验证、处置。
- **事件节奏**是加速器：新资产、新 CVE、新泄露触发定向重扫。
- **合规战役**是视图：按监管模板，从持续节奏的数据中抽取证据、生成台账与报告；它不是另一套系统。

### 5.2 端到端主流程（11 步）

| # | 步骤 | 目标 | 确定性动作 | AI 角色 | 单用户确认 | 输出 | 失败模式 | 指标 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 范围与授权 | 明确能看什么、能打什么 | 校验授权书、有效期、排除项、时间窗、限速 | 从合同/文档抽取范围建议 | 操作者确认 + 授权书哈希 + 主动扫描重认证 | Scope、Authorization、Confirmation | 无授权/越界 → 拒绝 + 审计 | 授权覆盖率、越界拒绝数 |
| 1 | 种子注入 | 告诉系统从哪里开始 | 根域、CIDR、云账号、代码组织、关键词、供应商 | 从组织信息/公开资料建议种子 | 操作者确认高影响种子 | SeedSet | 种子错误 → 发现偏离 | 种子命中率 |
| 2 | 持续发现 | 把未知变已知 | CT 日志、DNS、子域枚举、ASM API、云 API、代码托管、文档、暗网 | 查询生成、结果相关性、文档分类 | 影子资产入账确认（可配置） | Observation 流 | 源不可用/限流 → 降级 + 告警 | 新增资产/日、源覆盖率 |
| 3 | 身份归并 | 同一实体只有一个身份 | 归一化、指纹、别名、合并/拆分、归属判定 | 实体消歧建议、归属推断 | 合并高风险实体需确认 | Asset、Alias、Relationship | 误合并 → 可拆分 + 审计 | 去重率、归属率 |
| 4 | 暴露检测 | 找出可利用的暴露 | 端口/服务/指纹/目录/漏洞/密钥/文档/云配置 | 去噪、关联、解释 | 主动扫描需 scope + 重认证 + 冷却期 | FindingCandidate、Evidence | 工具失败/误报 → 重试/降级 | 发现数、工具成功率 |
| 5 | 验证 | 把候选变成可信结论 | 交叉信源、反证、复现、证据固化 | 假设生成、复现计划、证据摘要 | 严重级必须人工确认/自动复测 | Finding、Validation、Evidence | 无法复现 → 降级/待核查 | 验证覆盖率、误报率 |
| 6 | 评分与优先级 | 决定先修什么 | 四因子/控制覆盖/SLA/业务重要性 | 业务影响叙事、修复建议 | 风险接受需重认证 + 原因 + 到期 | RiskAssessment、Priority | 输入缺失 → 标注不确定 | 评分可复算率、SLA 命中 |
| 7 | 处置 | 让问题被修掉 | 建 Case、派 Owner、建工单、跟踪状态 | 修复方案草稿、工单草稿 | 对外通报需双通道确认 | Case、Action、Ticket | Owner 缺失 → 升级 | 分派及时率、MTTR |
| 8 | 复测与闭环 | 证明真的修好 | 重跑检测、证据比对、复发检测 | 复测计划、差异解释 | 操作者确认 + 证据；制度上补复测独立性 | Verification、Closure | 复测失败 → 重开 | 闭环率、复发率 |
| 9 | 报告与通报 | 对内/对外讲清楚 | 聚合、模板、哈希、导出 | 受众化叙事、差距分析 | 报送/通报双通道确认 | Report、Notice、Package | 通道失败 → 重试/人工 | 及时率、回执率 |
| 10 | 学习 | 让下一轮更准 | 误报回流、规则调优、评测更新 | 根因分析、规则建议 | 规则发布需确认 | EvalSample、RuleVersion | 反馈缺失 → 指标漂移 | 误报率、AI 准确率 |

> **单用户模式的关键差别**：上表没有「第二个人审批」，只有「操作者的可追溯确认」。因此每一步的确认都必须带：方式（passkey/OTP）、理由、范围哈希、before/after 快照、时间戳。对对外通报、重大删除、批量导出，额外要求双通道 + 冷却期。制度上应明确：系统提供的是「可追溯的自我确认」，不是「双人复核」。

### 5.3 监管五阶段的正确位置：渠道与证据模板，不是主状态机

| 监管阶段 | 本质能力 | 在目标架构中的位置 | 主要渠道/工具 | 证据要求 | 产出 |
| --- | --- | --- | --- | --- | --- |
| P1 搜索引擎 | 公开信息发现 | Discovery 的一个 Connector 组 | 百度/搜狗/必应、搜索引擎 API | 查询语句、结果快照、时间戳 | 域名/页面/附件 Observation |
| P2 空间测绘 | 资产发现与建档 | Discovery 的 ASM/CT/DNS Connector 组 | Fofa/Quake/Hunter/crt.sh、DNS | 原始响应、证书、解析链 | Asset + Alias + Relationship |
| P3 端口目录 | 深度检测 | Detection 的主动扫描能力 | nmap/ffuf/目录扫描 | 命令、原始输出、速率、授权 | FindingCandidate + Evidence |
| P4 第三方渠道 | 外部泄露发现 | Discovery + Detection 的代码/文档/社交 Connector | GitHub/Gitee/GitLab、文库/网盘、社交 | 仓库/文件/提交、内容快照 | FindingCandidate + Evidence |
| P5 暗网兜底 | 地下渠道情报 | Discovery + Validation 的暗网 Connector | 暗网监测/情报源 | 样本、截图、哈希、来源 | Lead + Package + Finding |

**关键结论**：
- P1/P2 是**发现**，P3/P4/P5 是**发现 + 检测/验证**；它们不是同一粒度的线性阶段。
- 当前 sweep 把 P1–P5 都做成「对已有资产跑 classify」，导致 P1/P2 没有发现、P3/P4/P5 没有真实采集。
- 目标架构中，五阶段只决定「跑哪些 Connector、要哪些证据、生成什么合规材料」，不决定系统主状态。

### 5.4 状态机

#### 资产生命周期

~~~text
candidate -> confirmed -> active -> stale -> retired
      |          |          |
      +----------+----------+--> merged (into another asset)
~~~

- candidate：低置信/待归属（影子资产）；
- confirmed：人工或高置信规则确认；
- active：最近一次观察在窗口内；
- stale：超过 N 天未观察到；
- retired：确认下线；
- merged：被合并，保留 alias 与历史。

#### Finding 生命周期

~~~text
new -> triaged -> validating -> confirmed -> remediating -> verified -> closed
  |       |           |            |              |
  |       |           +-> inconclusive -> validating
  |       +-> false_positive
  +-> duplicate
confirmed -> risk_accepted (confirmation_id + expires_at) -> reopened on expiry
closed -> reopened (regression)
~~~

#### 处置 Case

~~~text
open -> assigned -> in_progress -> pending_verify -> verified -> closed
  ^         |            |               |              |
  +---------+------------+---------------+--------------+--> reopened
~~~

#### 战役 Campaign

~~~text
draft -> confirmed -> running -> paused -> completed -> reported -> archived
~~~

#### 确认 Confirmation

~~~text
requested -> confirmed -> consumed
          -> rejected
          -> expired
~~~

#### 任务 Job

~~~text
queued -> leased -> running -> succeeded
                    |-> failed -> queued (retry) -> dead
                    |-> canceled
~~~

### 5.5 职责与 RACI（单用户）

| 活动 | 监管操作员 | 系统/AI | 被监管单位 | 外部通道 | 审计 |
| --- | --- | --- | --- | --- | --- |
| 定义辖区/授权 | R/A | C | C | I | I |
| 持续发现 | A | R | I | I | I |
| 身份归并 | R/A | C | I | I | I |
| 检测 | A | R | I | I | I |
| 验证 | R/A | C | I | I | I |
| 评分/优先级 | R/A | C | I | I | I |
| 处置 | R/A | C | C | I | I |
| 复测/闭环 | R/A | C | I | I | I |
| 对外通报 | R/A | C | I | C | C |
| 报告 | R/A | C | I | I | C |
| 规则/评测 | R/A | C | I | I | C |

> R=负责执行，A=最终负责，C=被咨询，I=被通知。单用户模式下操作员同时是 R 和 A；AI 永远是 C/R（辅助），不做 A。  
> **必须写进制度**：单用户模式无法实现真正的职责分离。系统能做的是「让每一次自我确认都可追溯」，不能做的是「让第二个人真实存在」。如果监管流程强制要求双人复核，应通过外部会签/纸质签批补足，而不是在系统里假装。

### 5.6 运营节奏

| 频率 | 动作 | 产出 | 负责人 |
| --- | --- | --- | --- |
| 实时 | 事件触发发现/检测/告警 | 案件、告警 | 平台 |
| 每日 | 新增资产/高危发现 review；队列健康 | 日报、异常清单 | 安全运营 |
| 每周 | 验证积压、SLA 风险、误报复盘 | 周报、调优项 | 运营负责人 |
| 每月 | 覆盖率、MTTR、复发率、AI 质量 | 月报 | 安全负责人 |
| 每季度 | 授权复核、评测集更新、DR 演练 | 合规材料、演练报告 | 负责人 + 审计 |
| 每半年 | 架构评审、容量规划、供应链审计 | 架构决策记录 | 架构师 |

---

## 6. 阶段功能设计：从可交付到可运营

### 6.1 阶段总览

| 阶段 | 时间 | 主题 | 核心目标 | 退出条件 |
| --- | --- | --- | --- | --- |
| **Phase 0** | 0–4 周 | 恢复可交付基线 | 绿色构建、单用户监管形态收口、CI 门禁、配置/迁移/停机 | go build/test 绿；CI 绿；文档/前端/schema 一致 |
| **Phase 1** | 1–3 月 | EASM 核心 | 资产身份、发现、暴露图、Finding、调度、处置 | 覆盖率/时效/验证率达标 |
| **Phase 2** | 3–6 月 | AI-native | Agent、Tool Gateway、证据 RAG、评测、Copilot | AI 质量/安全/成本达标 |
| **Phase 3** | 6–9 月 | 监管运营与外部协同 | OIDC/Passkey、辖区组合、报送/通报、集成、SLO/DR | 可 7×24 运营；审计可过 |
| **Phase 4** | 9–12 月 | 深化 | 云/容器/供应链/攻击路径/控制验证 | 高价值场景闭环 |

### 6.2 Phase 0：恢复可交付基线（0–4 周）

**目标**：把系统从历史上的「不可构建」拉回「可构建、可测试、可部署、可回滚」，并锁定「单用户监管台 + 被监管单位数据域」的正确语义。

**工作流 0.1：收口单用户形态（最高优先级）**

二选一，必须由负责人拍板：

- **方案 A（推荐，若单用户监管是最终形态）**：完成改造。
  1. **单 Operator**：保留一个登录主体；删除 R1–R8 角色矩阵；用能力开关控制主动扫描/对外通报/AI 写动作；
  2. **被监管单位数据域**：新增 regulated_entities；所有业务表带 entity_id；RLS 按 entity 隔离；保留 tenant 列作为 legacy 映射，不做破坏性 drop；
  3. **API**：删除 URL 中的 tenant；entity 相关资源用 /v1/entities/{eid}/... 或显式 entity_id 查询参数；Service/Store 保留 entityID 参数（从当前选择/principal 取，不由用户随意传）；
  4. **前端**：easm-live.js 去 /v1/tenants；增加被监管单位切换器与辖区组合视图；
  5. **单用户安全**：新增 confirmation 表 + 重认证 + 双通道 + 冷却期 + break-glass + 审计链；
  6. **文档/测试/OpenAPI** 同步。
- **方案 B（若还想保留多租户/多用户选项）**：回滚到 739e6f2，把当前改造保存为 patch/分支；用 strangler 重新做（先加 entity 兼容层，再切读路径）。

**工作流 0.2：工程基线**

- 新增 config 包：一个 Config 结构 + Load + Validate；所有 os.Getenv 收敛；启动打印脱敏配置摘要；
- 组装根重构：App/Deps 结构 + Build(cfg)；httpapi 按域拆 Router；消除 27 参数函数；
- 迁移工具：cmd/migrate + schema_migrations（up/status/plan/baseline；Makefile 不再手写）；
- HTTP 硬化：ReadTimeout/WriteTimeout/IdleTimeout、MaxHeaderBytes、body limit、security headers、request ID、panic recover、优雅停机；
- 健康检查：/healthz（liveness）+ /readyz（DB/对象存储/迁移版本）；
- 可观测：结构化日志 + request_id/trace_id；基础 metrics；启动/关闭日志；
- CI 门禁：build + test + vet + lint + trace + migration dry-run + OpenAPI diff（先占位）。

**工作流 0.3：契约与文档**

- OpenAPI 3.1 骨架（覆盖现有 110 路由，先保证路径/鉴权/响应骨架）；
- 错误码目录（code/HTTP/语义/处置）；
- ADR-001~012；
- AGENTS/README/CHANGELOG 与代码同步；
- live-smoke 改为「OpenAPI 路由 + 前端引用」双守卫。

**DoD**：
- go build ./... 绿；go test ./... 绿；make test-integ 绿（有 PG 时）；
- 单 Operator 可登录、可切换被监管单位、可拉取资产/台账/报告；
- 主动扫描/对外通报必须经过确认；确认记录可在审计中检索；
- 前端无 /v1/tenants 残留；
- 文档不再声称多租户/RLS，改为「单用户 + 被监管单位数据域」；
- CI 红灯即阻断合并；
- 迁移可从空库一键建到最新，且有版本表。

### 6.3 Phase 1：EASM 核心（1–3 月）

**目标**：让平台具备「自己看得见」的能力，并把发现变成可验证、可处置的闭环。

**功能域 1.1：资产身份与观察流**

- Asset/Alias/Observation/Relationship 表与 Service；
- 归一化规则：域名、IP、URL、证书、组件、凭据；
- 合并/拆分：指纹 + 置信度 + 人工确认；
- 生命周期：candidate/confirmed/active/stale/retired/merged；
- 迁移：现有 assets 回填为 Asset + Observation（source=legacy）。

**功能域 1.2：发现 Connector**

首批 5 个（按价值/成本排序）：
1. CT 日志（crt.sh / CertStream）：证书 SAN、子域；
2. DNS/子域枚举：字典 + 置换 + 泛解析识别；
3. ASM/测绘 API（Fofa/Quake/Hunter，按授权与配额）；
4. 代码托管（GitHub/Gitee/GitLab）：组织/仓库/提交/密钥；
5. 云资产（AWS/Azure/阿里云/腾讯云，只读 API）：公网 IP/存储/负载均衡。

每个 Connector：manifest、输入 schema、输出 Observation、fixture、健康检查、限流、错误分类。

**功能域 1.3：暴露图**

- 写入方补齐：owns/in_scope/resolves_to/cname/hosts/serves/uses/affects/leaks/valid_on/reachable/depends_on/observed；
- 边 provenance：source + evidence_ref + valid_from/valid_to；
- 查询：最短路径、可达、子图、TopN；深度/行数限制；
- 图与资产的一致性：投影器 + 对账任务。

**功能域 1.4：Finding 与验证**

- Finding 生命周期与 API；
- 三重门迁移为 Validation Policy（可配置、可测试）；
- 证据绑定：每个 Finding 至少 1 个 evidence_ref；
- 误报/重复/风险接受：状态、原因、确认、过期；
- 复核队列：低置信候选人工确认。

**功能域 1.5：调度与任务**

- PG job queue + worker pool + lease/heartbeat；
- 定时：每日发现、每周全量、每月战役；
- 事件：新资产、变更、新 CVE、新泄露；
- 取消/重试/死信/重放；
- 任务可观测：队列长度、等待时间、成功率、失败原因。

**功能域 1.6：处置与 SLA**

- Case/Action/Verification；
- Owner 分派、SLA、升级；
- 工单/通报/报告挂到 Case；
- 复发自动重开。

**功能域 1.7：辖区组合（最小）**

- regulated_entities 档案：名称/简称/区域/行业/等级/联系人/状态；
- 顶栏单位切换器；切换动作写审计；
- 单单位视图 + 辖区汇总（纳管数、覆盖率、未评估、超时通报、未闭环）；
- 所有查询/导出带 entity_id；跨单位聚合显式选择；
- 导出带单位标识、时间、水印、哈希。

**退出条件**：
- 真实数据下，资产覆盖率 ≥ 70%（对照种子与人工抽查）；
- 新增资产 P95 ≤ 24h；
- 严重级 100% 有验证证据；
- TopN 路径在真实图上非空（至少 3 类边有数据）；
- 任务队列可观测、可重试、无「永远 running」；
- 至少 3 家被监管单位可在同一平台内独立查看，报表/导出不串域。

### 6.4 Phase 2：AI-native（3–6 月）

**目标**：让 AI 成为运营团队的「调查员/研判员/报告员」，而不是一个聊天框。

**功能域 2.1：Agent Runtime**

- 案件级 AgentRun：上下文、计划、工具调用、证据、结论、成本；
- 步骤/预算/超时上限；checkpoint/resume；取消；
- 轨迹存储与回放；审计。

**功能域 2.2：Tool Gateway**

- MCP 工具注册：schema、risk_level、scope、rate limit、approval；
- 只读工具先行：search_assets、get_asset、graph_paths、list_findings、get_evidence、knowledge_search；
- 受控工具：create_case_draft、add_note、request_scan（需确认）；
- dangerous：scan_active、notify_external（禁止 AI 直接调用）。

**功能域 2.3：Context & Evidence RAG**

- 案件上下文：资产子图、Finding、证据片段、历史、规则/情报；
- 证据检索：按资产/时间/来源/类型；
- 引用格式：asset_id/finding_id/evidence_ref/URL；
- 脱敏：密钥、PII、内部 IP 按策略；
- 无证据时 abstain。

**功能域 2.4：Copilot 场景**

1. **调查 Copilot**：给定可疑资产/发现，汇总证据、提出假设、建议下一步（只读）。
2. **研判 Copilot**：解释严重级、去噪、建议优先级（不改事实）。
3. **修复 Copilot**：生成修复步骤、工单草稿、复测计划（人审）。
4. **报告 Copilot**：按受众生成叙事、差距分析、合规映射（引用证据）。
5. **第二双眼睛（单用户专用）**：高危动作前，AI 汇总当前证据、列出 3 个反方问题与可能后果；操作者可覆盖，但必须填理由。AI 只提示，不确认、不执行。

**功能域 2.5：评测与放量**

- 评测集：真实案件 + 人工标注；覆盖调查/研判/修复/报告；
- 指标：引用率、幻觉率、准确率、采纳率、成本、时延；
- 门禁：不达标不放量；影子/灰度/回滚；
- 反馈：采纳/拒绝/修正回流为样本。

**退出条件**：
- 只读 Copilot 在真实案件中使用率 ≥ 50%；
- 证据引用率 100%，幻觉率 ≤ 2%；
- 单案件成本可计量、可预算；
- 零越权工具调用、零未确认 dangerous 动作；
- dangerous 动作 100% 经过「第二双眼睛」提示（可覆盖但留痕）；
- 人工调查时长下降 ≥ 30%。

### 6.5 Phase 3：监管运营与外部协同（6–9 月）

**目标**：从「一个人能用」到「辖区可运营、可审计、可交接」。

- **单用户身份**：OIDC/passkey、会话/设备管理、break-glass、恢复演练；
- **辖区组合**：被监管单位档案、授权范围、联系人、评估计划、跨单位对比/排名/趋势；
- **监管闭环**：评估任务、通报（公安 24h / 通报中心 48h）、回执、整改跟踪、超时升级；
- **报送**：模板化材料、哈希/时间戳、导出包（md/pdf/zip）、水印、回执归档；
- **外部协同**：安全邮件、文件交换、ITSM（如工单）、报送通道；可选只读导出令牌；
- **数据域**：entity_id + RLS + 跨单位聚合的显式选择与审计；
- **SLO/DR**：指标、告警、备份/恢复、RTO/RPO 演练；
- **运营手册**：单人值班、交接、break-glass、年度授权复核。

**退出条件**：
- 单用户登录/重认证/双通道/break-glass 通过安全测试；
- 辖区组合视图可回答「哪些单位未评估、哪些通报超时、哪些整改未闭环」；
- 通报及时率 100%，报送材料一次通过率 ≥95%；
- 核心 SLO 达标 30 天；
- 恢复演练 RTO ≤4h、RPO ≤15min；
- 交接 runbook 完成并演练一次。

### 6.6 Phase 4：深化（9–12 月）

- 云原生资产：K8s/容器/镜像/CI-CD/供应链；
- 攻击路径：多跳、凭据、控制覆盖、业务影响；
- 控制验证：WAF/EDR/零信任策略是否真的生效；
- 外部情报：商业 ASM/暗网/漏洞源；
- 红队协同：只读/受控接口；
- 行业模板：监管报送、行业基线。

### 6.7 团队与容量假设

| 角色 | 人数 | 职责 |
| --- | --- | --- |
| 架构/技术负责人 | 1 | 架构决策、ADR、评审、跨域协调 |
| 后端 | 2 | 领域模型、数据、执行平面、集成 |
| 前端 | 1 | console 重构、可视化、交互 |
| 安全运营 | 1 | 场景、规则、验证、验收、外部对接 |
| QA/SRE | 1 | 测试、CI、可观测、发布、演练 |

> 最小 4 人（架构兼后端、后端、前端、安全运营）；6 人可并行 Phase 1/2。若只有 2 人，按 Phase 0 → 1 → 2 串行，砍掉 Phase 3/4，优先保证「发现—验证—处置」闭环。

### 6.8 不做清单（Phase 0–2）

- 不做多租户 SaaS/计费/客户切换；
- 不做自研扫描器/爬虫引擎（用插件）；
- 不做全量图数据库/向量库替换（先 PG）；
- 不做 AI 自动扫描/自动通报/自动闭环；
- 不做大而全的 19 视图重写（先核心 6 视图：驾驶舱、资产、发现、案件、报告、设置）；
- 不做 K8s/容器化（单机优先）；
- 不做「一次性完美迁移」（先双写/投影/回滚）。

### 6.9 能力矩阵（按阶段）

| 能力 | Phase 0 | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
| --- | --- | --- | --- | --- | --- |
| 绿色构建/CI | ✓ | ✓ | ✓ | ✓ | ✓ |
| 单用户监管台 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 被监管单位数据域 | 骨架 | ✓ | ✓ | ✓ | ✓ |
| 资产身份/观察流 |  | ✓ | ✓ | ✓ | ✓ |
| 发现 Connector |  | 5 个 | +2 | +2 | +云/供应链 |
| 暴露图全关系 |  | ✓ | ✓ | ✓ | ✓ |
| Finding 生命周期 |  | ✓ | ✓ | ✓ | ✓ |
| 调度/队列 |  | ✓ | ✓ | ✓ | ✓ |
| 处置/SLA |  | ✓ | ✓ | ✓ | ✓ |
| 单用户重认证/双通道 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Agent Runtime |  |  | ✓ | ✓ | ✓ |
| Tool Gateway/MCP |  | 骨架 | ✓ | ✓ | ✓ |
| 证据 RAG |  |  | ✓ | ✓ | ✓ |
| 评测/放量 |  |  | ✓ | ✓ | ✓ |
| 辖区组合/跨单位对比 |  | 骨架 | ✓ | ✓ | ✓ |
| 报送/通报/回执 |  | 骨架 | ✓ | ✓ | ✓ |
| OIDC/Passkey/Break-glass |  |  |  | ✓ | ✓ |
| 外部协同/集成 |  |  |  | ✓ | ✓ |
| SLO/DR |  | 骨架 | ✓ | ✓ | ✓ |
| 云/供应链 |  |  |  |  | ✓ |

## 7. 迁移策略：从当前状态到目标架构

### 7.1 第一件事：恢复绿色基线（二选一，必须拍板）

| 方案 | 做法 | 优点 | 代价 | 适用 |
| --- | --- | --- | --- | --- |
| **A. 完成单用户化** | 保留领域层改动，补齐 httpapi/pgstore/tests/schema/frontend/docs | 不浪费已有工作；一步到位 | 首批已落地；剩余约 8–12 人日（前端确认面板、完整 WebAuthn、IdP 联调） | 单用户监管是最终形态 |
| **B. 回滚重做** | 保存当前 diff 为 patch/分支；回到 739e6f2 绿色基线；用 strangler 重做 | 立刻可交付；风险低 | 丢弃/重做部分工作；约 10–15 人日 | 还需要保留多租户选项/时间紧 |

**无论选哪个，都不允许继续在红色树上叠功能。** 这是 Phase 0 的第一条纪律。

### 7.2 单用户 + 被监管单位数据域的正确做法

#### 7.2.1 数据模型

不要删除 tenant_id，而是**改变它的语义**：

- 新增 regulated_entities（id, name, short, region, industry, level, contact, status）；
- 所有业务表的 tenant_id 改名为 entity_id（或保留列名，代码映射为 entityID）；legacy 行默认 default，新写入必须显式 entity_id；
- 新增 scope_id（授权范围）、owner_id（被监管单位责任人）、campaign_id（评估批次）；
- RLS 策略按 entity_id 隔离；应用连接设置 easm.entity_id；无设置时拒绝（不是穿透）；
- 保留 tenants 表作为 legacy 映射，至少两个 release 后再清理。

#### 7.2.2 代码签名

当前改造把 tenant 参数从 Service/Store 全部删除，这是**过度删除**。正确做法：

- **URL**：不出现 tenant；被监管单位资源用 /v1/entities/{eid}/...，因为 entity 是数据域，不是 SaaS 客户；
- **Principal**：单 operator；当前选择的 entity 放在 context/session，不放在用户可伪造的 header；
- **Service/Store**：保留 entityID 参数（从 context 取），禁止使用「全局默认」隐式穿透；
- **跨域调用**：显式传递 entityID；跨 entity 聚合必须显式声明。

这样既简化了单用户 API，又保留了数据域隔离。

#### 7.2.3 单用户安全

- 不建用户/角色矩阵；保留一个 operator；
- 能力开关：read_only / scan_passive / scan_active / intrusive_scan / notify_external / export / ai_enabled；
- Confirmation：高危动作前重认证 + 理由 + 范围哈希 + 冷却期；对外通报双通道；
- break-glass：离线恢复码/备用凭据；使用即告警 + 审计；
- 审计链：actor + session + device + IP + entity + action + before/after hash。

#### 7.2.4 迁移 023

1. 创建 regulated_entities；从 tenants 回填（若已有数据）；
2. 业务表增加 entity_id（legacy 行默认 default，新写入必须显式），从 tenant_id 回填；
3. RLS 策略改为 entity_id；应用连接设置 easm.entity_id；
4. 保留 tenant_id 作为 legacy 列；不做破坏性 drop；
5. 数据校验：每个 entity 的资产/发现/报告数量对账；
6. 回滚：保留旧列与旧策略，可切回。

#### 7.2.5 前端

- 顶栏「被监管单位切换器」；默认显示辖区聚合；
- 资产/发现/报告视图按 entity 过滤；
- 跨单位聚合必须显式选择「全部单位」，并显示聚合口径；
- 导出带 entity 标识、时间、水印；
- 高危动作弹出确认面板：目标、范围、速率、影响面、理由、重认证。

#### 7.2.6 不要做什么

- 不要建用户/角色/SCIM 表；
- 不要删除 entity_id / RLS；
- 不要用「单账号」替代确认与审计；
- 不要把 entity 当成 tenant 做 SaaS 计费；
- 不要让 AI 直接执行 dangerous 动作。

### 7.3 台账 → Finding + 合规投影

**目标**：不让现有报表/API 破裂，同时让新流程独立。

步骤：

1. 新建 findings、finding_evidence、validations、risk_assessments、remediation_cases、verifications 表；
2. 回填：ledger_items → findings（尽量保留 ID 映射）+ ledger_projection（保留原字段）；
3. 双写：新 Finding 创建时，若命中合规规则，生成/更新 LedgerEntry；
4. 双读：报表先读 ledger_projection（兼容），逐步切 Finding；
5. 旧写路径：保留 POST /v1/ledger 作为兼容入口，内部转 Finding；
6. 下线：至少两个 release 后，再把 ledger 表改为只读投影。

**关键**：不要一次性重写 ledger；它是当前最可信的资产，必须保留其状态机与三重门，只是把「事实源」上移一层。

### 7.4 双后端 → PG-first

- 生产只允许 PG；内存后端仅用于单测/演示，且必须显式 EASM_BACKEND=memory，不能在 PG 失败时静默回退。
- 每个 Store 接口配一套**契约测试**，Mem/PG 都跑同一套；PG 集成测试必须真实执行（不能 skip 掩盖）。
- 逐步用 sqlc/代码生成替代手写 Scan；至少做到「列清单单一来源」，避免加字段漏列。
- 迁移工具替代 Makefile 手写清单；每个迁移有 up/down；CI 跑空库迁移 + 现有库 dry-run。

### 7.5 前端：从演示单页到可维护客户端

当前 console 是 260KB app.js + 56KB live 层 + 60KB HTML，存在「演示数据」与「真实数据」双路径，且仍请求 /v1/tenants。建议：

1. **短期**：拆 app.js 为 ES modules（api client、views、components、state）；删除 demo 数据路径；所有视图只读真实 API；用 MSW/fixture 做开发。
2. **中期**：引入 React/TS + Vite（或保留零依赖但用模块化 + 类型 JSDoc）；从 OpenAPI 生成 typed client；组件库/设计令牌。
3. **长期**：性能预算（首屏 ≤ 3s、视图切换 ≤ 1s）、可访问性、错误边界、离线提示。
4. **迁移方式**：新 shell + 旧视图 iframe/并行路由，逐视图替换；不要一次性重写。

### 7.6 AI：从旁路到有界 Agent

1. **只读阶段**：Agent 只能调用 search/get/list/graph/evidence；输出 suggestion；不写状态。
2. **受控阶段**：允许 create_case_draft/add_note/request_scan（后者进入确认队列）。
3. **确认阶段**：dangerous 工具只能由人触发；AI 可准备参数但不能执行。
4. **放量阶段**：评测达标后，按案件类型/用户群灰度。
5. **回滚**：feature flag + 模型/Prompt 版本固定；一键关闭。

### 7.7 文档与追溯

- 每个架构决策写 ADR（§8）；
- OpenAPI 作为 API 唯一契约；CI 做 breaking change 检查；
- AGENTS/README/CHANGELOG 与代码同批更新；
- trace-check 扩展：不仅检查包注释编号，还检查「路由 ↔ OpenAPI ↔ 前端引用」；
- 每季度做一次「文档-代码一致性」审计。

### 7.8 迁移顺序（建议）

| 周 | 工作 | 产出 | 依赖 |
| --- | --- | --- | --- |
| 0–1 | 拍板 A/B；冻结功能；备份 patch/分支 | 决策记录、备份 | 无 |
| 1–2 | 恢复 build：httpapi + pgstore | 编译绿 | 决策 |
| 2–3 | 恢复 test：单测/集成/前端 | 测试绿 | 编译 |
| 3–4 | entity 数据域迁移 023 + 单用户确认 | 单用户监管形态 | 编译 |
| 4–5 | config/组装根/停机/健康检查/迁移工具 | 可运维基线 | 测试绿 |
| 5–6 | OpenAPI + CI 门禁 + 文档同步 | 契约基线 | API 稳定 |
| 6–10 | Asset/Observation/Graph/Finding | EASM 核心数据 | Phase 0 |
| 10–14 | Discovery Connector + Scheduler/Job | 持续发现 | 数据模型 |
| 14–18 | Case/SLA/Verification + 报表投影 | 闭环 | Finding |
| 18–24 | Agent/Tool Gateway/RAG/Eval | AI-native | 核心数据 |
| 24–36 | OIDC/辖区组合/报送/集成/SLO/DR | 监管运营 | 全部 |

### 7.9 回滚预案

- 每个迁移有 down；每个新路径有 feature flag；每个阶段有 tag。
- 数据迁移先双写、后切读；保留旧表至少两个 release。
- 回滚演练：在 staging 上每季度做一次「升级→回滚→再升级」。
- 红色构建期间禁止发布；CI 红灯即阻断。


---

## 8. 关键决策记录（ADR）

### ADR-001：五阶段是合规战役模板，不是系统主干

- **背景**：当前 sweep 把 P1–P5 做成线性流水线，但 P1/P2 没有发现能力，导致「有治理无输入」。
- **决策**：主干改为持续 EASM 运营环；P1–P5 作为 Campaign 模板与证据要求映射。
- **后果**：需要重构 sweep；保留五阶段 API 作为战役入口；报表口径不变。
- **替代方案**：继续把五阶段当主干（否决：无法表达持续发现/变更/验证）。

### ADR-002：单用户监管台 + 被监管单位数据域

- **背景**：使用形态收敛为监管单位单用户；多用户 RBAC/审批分离不再适用。
- **决策**：单 Operator；被监管单位（entity_id）作为一等数据域；RLS 按 entity 隔离；不建用户/角色矩阵。
- **后果**：需要单用户安全补偿（重认证/双通道/冷却期/审计/break-glass）；需要辖区组合视图；API 以 entity 为中心。
- **替代方案**：继续多用户 RBAC（否决：与使用形态冲突）；完全无数据域（否决：辖区多单位会串域）。

### ADR-003：PostgreSQL 为唯一事实源，图先落 PG

- **背景**：多模存储（Neo4j/OpenSearch/ClickHouse/Redis）在单机形态下过重。
- **决策**：PG 存资产/关系/发现/案件/事件；图查询用递归 CTE；Neo4j 作为可选 Provider；对象存储存证据。
- **后果**：需要设计好索引与查询上限；大规模图再切 Neo4j。
- **替代方案**：直接上 Neo4j（否决：运维复杂、当前规模不需要）。

### ADR-004：跨域事件用 Transactional Outbox

- **背景**：跨域一致性靠手工补偿，无法重放/审计。
- **决策**：所有跨域状态变化写 outbox；消费者至少一次 + 幂等键；DLQ + 重放。
- **后果**：需要事件目录与消费者治理；增加一张表与一个发布器。
- **替代方案**：直接双写（否决：不一致不可查）。

### ADR-005：任务队列先用 PG，Temporal 可选

- **背景**：当前只有进程内同步执行与可选 Temporal；无持久队列。
- **决策**：PG job 表 + SKIP LOCKED + lease/heartbeat；规模上来再换 Temporal；接缝不变。
- **后果**：需要实现租约/重试/死信；单机足够。
- **替代方案**：直接上 Temporal（否决：当前部署约束与复杂度）。

### ADR-006：AI 只做有界 Agent，不做事实源

- **背景**：AI 旁路无法完成调查；直接放开又破坏不造假。
- **决策**：Agent Runtime + Tool Gateway + 证据/评测/确认/成本五闸；AI 只写 suggestion/action request。
- **后果**：需要工具 schema、评测集、轨迹审计；上线慢但可控。
- **替代方案**：让模型直接产出 Finding（否决：不可验证、不可审计）。

### ADR-007：Ledger 降为合规投影

- **背景**：ledger 同时承担发现/合规/处置/复测/通报，耦合严重。
- **决策**：Finding/Case 为事实源；LedgerEntry 为投影；保留 API 兼容。
- **后果**：需要双写/回填/双读；短期复杂度上升，长期解耦。
- **替代方案**：继续以 ledger 为中心（否决：无法表达非合规发现与生命周期）。

### ADR-008：生产禁止内存后端静默回退

- **背景**：内存/PG 双后端导致行为漂移，且 PG 失败可能被掩盖。
- **决策**：生产只允许 PG；内存显式开关仅测试/演示；PG 不可用 fail loud。
- **后果**：部署更严格；测试需 PG 集成。
- **替代方案**：继续双后端（否决：漂移成本高于收益）。

### ADR-009：OpenAPI 是 API 唯一契约

- **背景**：114 条路由无完整 schema 契约，前端手写路径，live-smoke 靠正则。
- **决策**：OpenAPI 3.1 + 生成客户端 + CI breaking change 检查。
- **后果**：需要维护 spec；短期投入，长期降低联调成本。
- **替代方案**：继续手写（否决：漂移不可控）。

### ADR-010：禁止 big-bang 跨层改造

- **背景**：单用户化一次改六层，导致 161 个编译错误。
- **决策**：所有跨层改造走 strangler；每步可编译/可测试/可回滚；feature flag。
- **后果**：交付节奏更慢但更稳；需要兼容层。
- **替代方案**：继续 big-bang（否决：当前已证明代价）。

---

### ADR-011：单用户安全补偿

- **背景**：单用户无法实现双人审批/职责分离；但高危动作仍需防误操作、防滥用、可追溯。
- **决策**：用「重认证 + 双通道确认 + 冷却期 + 干跑/范围预览 + 强制理由 + 审计链 + break-glass」补偿；不假装有第二个人。
- **后果**：高危动作多一步确认；需要 passkey/OTP 基础设施；制度上需明确「自我确认」的效力边界。
- **替代方案**：只靠密码/只靠日志（否决：无法防止误操作与凭据滥用）。

### ADR-012：被监管单位是一等数据域

- **背景**：监管单位要管理辖区多家单位；单用户不等于单数据域。
- **决策**：regulated_entities + entity_id + RLS；单用户切换 entity；跨 entity 聚合显式选择并留痕。
- **后果**：所有查询/导出必须带 entity；报表/材料按 entity 标识；迁移需要回填与对账。
- **替代方案**：用标签/目录区分（否决：无法做行级隔离与可靠报表）。

## 9. 风险与反脆弱

| 风险 | 触发信号 | 影响 | 缓解 |
| --- | --- | --- | --- |
| 范围蔓延 | 每个阶段都想加功能 | 核心能力迟迟不落地 | 阶段门禁 + 「不做清单」 |
| 数据源不可用/限流 | Connector 失败率上升 | 覆盖率下降 | 多源冗余、退避、降级标注 |
| 误报率上升 | 验证积压、人工推翻率高 | 信任下降 | 三重门、评测集、抑制规则 |
| AI 幻觉/注入 | 无引用结论、越权工具调用 | 安全事故 | 五闸、红队、评测、确认 |
| 供应链/插件风险 | 未知二进制、许可证问题 | 合规/安全 | 签名、SBOM、白名单、CLI 隔离 |
| 单点/容量 | 队列积压、DB 连接耗尽 | 不可用 | 限流、背压、水平扩展、SLO |
| 迁移失败 | 双写不一致、回滚失败 | 数据损坏 | 双写校验、dry-run、备份、回滚演练 |
| 团队容量 | 关键人依赖 | 进度风险 | 文档/ADR/配对/自动化 |
| 合规变化 | 报送格式/时限变化 | 返工 | 模板化、配置化、单点挂接 |
| 成本失控 | AI/扫描费用超预算 | 不可持续 | 成本闸、配额、预算告警 |


### 9.1 单用户模式特有风险

| 风险 | 触发信号 | 影响 | 缓解 |
| --- | --- | --- | --- |
| 凭据被盗/丢失 | 异常登录、异地登录、失败重认证 | 全平台失守 | passkey/OTP、会话超时、IP 白名单、break-glass、审计告警 |
| 单点决策/疲劳 | 确认弹窗过多、批量操作增多 | 误操作、漏看 | 批量确认、模板、检查清单、AI 反方提问、冷却期 |
| 被监管单位数据串域 | 报表/导出出现其他单位数据 | 监管事故 | entity_id + RLS + 导出水印 + 跨域测试 |
| 监管数据敏感性 | 敏感材料外带、截图泄露 | 合规风险 | 加密、脱敏、水印、导出确认、保留期 |
| 连续性/交接 | 休假、离职、设备损坏 | 业务中断 | break-glass、恢复演练、交接 runbook、加密备份 |
| 审计被篡改 | 日志缺失、哈希断链 | 无法追责 | append-only、哈希链、日/周锚定、异机备份 |
| 过度依赖 AI | 无引用结论、直接采纳 | 误判 | 证据引用、评测、人工确认、AI 不可确认 |
| break-glass 滥用 | 非计划使用、无登记 | 绕过正常控制 | 离线保管、使用告警、事后复盘、定期轮换 |

**反脆弱设计**：
- 任何外部依赖失败都不应让主流程「假装成功」；返回明确降级状态。
- 任何自动化动作都要有「人工接管」按钮。
- 任何新能力都要有「关闭开关」。
- 任何结论都要有「证据/置信度/时间」三要素。

---

## 10. 验收与度量

### 10.1 架构适应度函数（CI 可执行）

| # | 检查 | 工具 | 失败后果 |
| --- | --- | --- | --- |
| AF-1 | go build ./... | CI | 阻断合并 |
| AF-2 | go test ./... + 集成测试 | CI | 阻断合并 |
| AF-3 | 领域包不依赖 httpapi/pgstore | import 检查 | 阻断合并 |
| AF-4 | os.Getenv 只在 config 包 | grep/AST | 阻断合并 |
| AF-5 | 路由 ↔ OpenAPI ↔ 前端引用一致 | 脚本 | 阻断合并 |
| AF-6 | 迁移 up/down/dry-run | CI + PG | 阻断合并 |
| AF-7 | 每个 Finding 有 evidence_ref | 单测/约束 | 阻断合并 |
| AF-8 | dangerous 工具必须确认 | 单测/策略测试 | 阻断合并 |
| AF-9 | AI 工具调用全量审计 | 集成测试 | 阻断合并 |
| AF-10 | 图边必须有 source/provenance | 约束/单测 | 阻断合并 |

### 10.2 业务 KPI

| 维度 | 指标 | 口径 | 目标 |
| --- | --- | --- | --- |
| 监管覆盖 | 辖区被监管单位纳管率 | 已纳管/辖区总数 | ≥ 95% |
| 监管覆盖 | 授权范围覆盖率 | 有有效 scope/应纳管 | 100% |
| 评估 | 周期评估完成率 | 已完成/计划 | 100% |
| 发现 | 新增资产入账 P95 | 观察到入库 | ≤ 24h |
| 发现 | 事件触发检测 P95 | 事件到任务开始 | ≤ 5min |
| 质量 | 严重级验证覆盖率 | 有复测证据/严重级总数 | 100% |
| 质量 | 误报率 | 人工推翻/已确认 | ≤ 5% |
| 通报 | 公安 24h 及时率 | 24h 内/应通报 | 100% |
| 通报 | 通报中心 48h 及时率 | 48h 内/应通报 | 100% |
| 整改 | 高危 MTTR P95 | 确认到闭环 | ≤ 7d |
| 整改 | 整改闭环率 | 按时闭环/应闭环 | ≥ 90% |
| 整改 | 复发率 | 30 天内复发/已闭环 | ≤ 10% |
| 报送 | 材料一次通过率 | 一次通过/提交 | ≥ 95% |
| AI | 证据引用率 | 有引用/全部结论 | 100% |
| AI | 幻觉率 | 无证据/矛盾/全部 | ≤ 2% |
| AI | 采纳率 | 采纳/建议 | ≥ 60% |
| 运营 | 核心 API 可用性 | 月度 | ≥ 99.9% |
| 运营 | 任务队列 P95 等待 | 月度 | ≤ 60s |
| 审计 | 高危动作确认覆盖率 | 有确认/高危动作 | 100% |
| 审计 | 审计可回溯率 | 可定位/抽样 | 100% |

> 所有指标默认按被监管单位单列；辖区聚合视图必须显示口径、样本量与时间窗口。监管单位的价值不是「发现最多」，而是「辖区无遗漏、通报不超时、整改有闭环、材料可复核」。

### 10.3 验收节奏

- **每周**：Phase 0/1 工程门禁 + 数据质量抽样。
- **每两周**：Demo + 回顾；风险登记更新。
- **每月**：KPI 复盘；架构债务清单更新。
- **每季度**：架构评审 + DR 演练 + 评测集更新。
- **每半年**：外部评审/渗透测试/合规审计。


---

## 11. 监管单位单用户模式专项设计

### 11.1 监管单位的能力模型

监管单位不是「一家企业的安全部」。两者的第一性差异不在功能多少，而在「资产归属、处置主体、成功标准」：

| 维度 | 企业自用 EASM | 监管单位 EASM |
| --- | --- | --- |
| 资产归属 | 自己的资产 | 辖区内被监管单位的资产 |
| 处置主体 | 自己的运维/安全团队 | 被监管单位；监管单位负责通报、跟踪、复核 |
| 核心动作 | 发现→修复→复测 | 评估→通报→整改跟踪→复测→报送 |
| 成功标准 | MTTR、复发率 | 辖区覆盖率、通报及时率、整改闭环率、材料可复核 |
| 数据边界 | 单组织 | 多被监管单位数据域（entity_id） |
| 权限模型 | 多角色 | 单用户 + 重认证/双通道 + 审计 |

因此能力模型要围绕「组合管理」而不是「单单位资产清单」：

| 能力 | 说明 | 关键数据 | 关键界面 |
| --- | --- | --- | --- |
| 辖区组合 | 辖区内被监管单位清单、分层分类、评估状态 | entity、region、industry、level、contact | 辖区驾驶舱、单位列表、地图/分组 |
| 单位档案 | 每家单位的根域/CIDR/云账号/责任人/授权书 | entity、scope、authorization | 单位详情、授权管理 |
| 周期评估 | 按季度/专项发起 P1–P5 评估 | campaign、stage、task | 评估计划、进度矩阵 |
| 通报整改 | 通报、回执、整改跟踪、超时升级 | notice、receipt、case、SLA | 通报名单、超时看板 |
| 报送 | 汇总材料、模板、哈希、导出 | report、package、hash | 报送中心、导出包 |
| 跨单位对比 | 覆盖率、发现率、整改率、复发率排名 | metrics、benchmark | 对比表、趋势图 |
| 证据与审计 | 每条结论可回溯；每次动作可审计 | evidence、audit | 证据抽屉、审计检索 |

**关键洞察**：监管单位的「资产」不是自己的资产，而是「辖区单位的暴露面」。因此 entity_id 必须贯穿资产、发现、报告、通报、导出的全链路；否则辖区报表一定串域。

### 11.2 单用户不是单安全层

单用户模式无法实现真正的职责分离。必须用「可追溯的自我确认」补偿，并如实登记残余风险：

| 威胁 | 多用户控制 | 单用户补偿 | 残余风险 |
| --- | --- | --- | --- |
| 误操作 | 双人审批 | 重认证 + 范围预览 + 冷却期 + 干跑 | 操作者仍可能确认错误 |
| 滥用 | 分权 | 能力开关 + 速率/配额 + kill switch + 审计 | 有权限者仍可作恶 |
| 凭据泄露 | MFA + RBAC | passkey/OTP + 会话超时 + IP 白名单 + break-glass | 终端被控仍可能失守 |
| 内部人 | 职责分离 | 强制理由 + before/after + 审计锚定 + 外部抽查 | 无法完全防止共谋/单人决策 |
| 数据串域 | 租户隔离 | entity_id + RLS + 导出水印 + 跨域测试 | 配置错误仍可能泄露 |
| 审计篡改 | 双审计 | append-only + 哈希链 + 日/周锚定 + 异机备份 | 拥有主机权限者仍可破坏 |
| 连续性 | 多人备份 | break-glass + 恢复码 + 交接 runbook + 演练 | 单点依赖仍存在 |

> 结论：单用户模式是「效率优先、可控可追溯」的形态，不是「安全等价于多用户」。如果监管制度要求双人复核，必须在制度层做外部会签，不能靠系统假装。

### 11.3 单用户 UX

单用户的效率决定平台是否真的被使用。建议：

- **命令面板**：全局搜索资产/单位/发现/报告；键盘优先；
- **辖区驾驶舱**：今日待办、超时通报、待验证、待整改、异常源；
- **单位切换器**：顶栏切换；切换动作写审计；跨单位聚合显式选择；
- **批量操作**：批量确认、批量分派、批量导出；风险分级，低风险不弹窗；
- **模板**：评估模板、通报模板、报告模板、修复话术；
- **复核模式**：AI 先总结证据、提出 3 个反方问题，操作者确认/覆盖；
- **差异视图**：本次评估 vs 上次；新增/消失/变化；
- **导出中心**：材料、哈希、回执、水印、历史；
- **确认疲劳控制**：只读不确认；低风险一次确认；高风险重认证；同一 scope 短期复用确认（但每次动作仍留痕）。

### 11.4 单用户运营节奏

| 频率 | 动作 | 产出 |
| --- | --- | --- |
| 每日 | 看辖区待办、超时通报、新增高危、失败任务 | 日清单 |
| 每周 | 跨单位对比、验证积压、误报复盘 | 周报 |
| 每月 | 覆盖率、MTTR、整改率、AI 质量、报送 | 月报 |
| 每季度 | 授权复核、评测集更新、DR 演练、break-glass 轮换 | 合规材料/演练报告 |
| 每半年 | 架构评审、容量规划、供应链审计 | ADR/改进项 |

### 11.5 连续性与交接

- break-glass 离线保存（密封/双人保管），使用即告警 + 登记 + 复盘；
- 恢复码打印/密封，定期轮换；
- 加密备份 + 每季度恢复演练；
- 交接 runbook：账号、凭据、恢复、常用任务、外部联系人；
- 单点风险登记：一人休假/离职时的最小可运营方案；
- 关键操作留痕，确保交接后仍可追溯。

### 11.6 边界与不做什么

- 不做多用户 RBAC、用户/角色管理、SCIM；
- 不做 SaaS 多租户计费/客户切换；
- 默认不建第二个登录账号；如确需，先只读导出令牌，再 break-glass，最后才考虑 observer；
- 不做 AI 自动确认/自动通报/自动闭环；
- 不把「单用户」当成「单安全层」；不把「确认弹窗」当成「双人审批」；
- 不在制度未确认的情况下声称满足双人复核要求。

## 附录 A：现状量化证据

| 指标 | 数值 | 说明 |
| --- | --- | --- |
| Go 文件 | 190 | platform + cmd |
| Go LOC | 33,293 | 含测试 |
| 测试文件 | 93 | 单测 + 集成 |
| 测试 LOC | 13,988 | 约 42% |
| 业务包 | 48 | internal/* |
| HTTP 路由 | 117 | httpapi/server.go（OpenAPI 生成口径） |
| Handler | 92 | 各 domain handler 文件 |
| MCP 工具 | 16 | mcp/server.go |
| 迁移文件 | 29 | 001–029 |
| 表 | 27 | 含 confirmations 与 legacy tenants |
| 索引 | 23 | 迁移内 |
| SQL LOC | 566 | 迁移 |
| env 变量 | 28 | os.Getenv |
| NewMemStore 文件 | 51 | 双后端面 |
| 编译错误 | 0（Phase 0 恢复后） | 历史 161 / 33 文件；当前 go build 通过 |
| console app.js | 260KB | 单文件 |
| console easm-live.js | 56KB | 仍请求 tenants |
| console index.html | 60KB | 静态视图 |
| 前端函数 | 451 | app.js |

**关键证据位置**：
- 构建错误：go build -gcflags=-e ./...（本次实测；默认 build 截断为 22 条）。
- 单用户化：cmd/server/main.go 包注释、各 domain 的 tenant 字段删除。
- 权限模型：internal/rbac/rbac.go（单 admin；单用户模式下可接受，但缺重认证/确认/break-glass）。
- 辖区组合缺失：无 regulated_entities / portfolio 模型，无法按被监管单位隔离报表。
- 单用户确认缺失：无 confirmation / reauth / 双通道记录。
- Schema 未迁移：migrations/001_init.sql（tenants、assets.tenant_id、RLS）。
- 前端未迁移：console/easm-live.js（/v1/tenants）。
- sweep 只做判敏：internal/sweep/sweep.go（run() 循环 classify）。
- 图谱边窄：internal/ingest/ingest.go（resolves_to）、internal/secret/secret.go（leaks）。
- 无 OpenAPI：仓库无 openapi/swagger 文件。
- 无优雅停机：cmd/server/main.go（仅 ReadHeaderTimeout，ListenAndServe 直出）。
- 迁移手工（改造前）：Makefile 逐条 psql；现已由 cmd/migrate + schema_migrations 取代。

---

## 附录 B：目标 API 面（建议）

> 保留现有 /v1/* 作为兼容层；新能力按资源化设计。单用户模式下，entity 是数据域，不是 SaaS 租户；URL 里出现 entity 是合理的，但权限仍由服务端校验。

| 资源 | 端点（示例） | 说明 |
| --- | --- | --- |
| 会话 | POST /v1/session；POST /v1/session/reauth；POST /v1/session/breakglass | 单用户登录、重认证、break-glass |
| 被监管单位 | GET/POST /v1/entities；GET/PATCH /v1/entities/{eid} | 辖区组合、单位档案 |
| 资产 | GET/POST /v1/entities/{eid}/assets；GET /v1/entities/{eid}/assets/{id}；GET .../graph | 现有 + 图，按 entity 过滤 |
| 观察 | GET /v1/entities/{eid}/observations?asset_id=&source=&from=&to= | 新增 |
| 发现 | GET/POST /v1/entities/{eid}/findings；POST .../findings/{id}:validate | 新增 |
| 案件 | GET/POST /v1/entities/{eid}/cases；POST .../cases/{id}:assign/:verify/:close | 新增 |
| 授权 | GET/POST /v1/entities/{eid}/scopes；POST .../scopes/{id}:revoke | 新增 |
| 确认 | POST /v1/confirmations；GET /v1/confirmations/{id} | 高危动作确认/重认证 |
| 任务 | GET/POST /v1/jobs；POST /v1/jobs/{id}:cancel/:retry | 新增 |
| 战役 | GET/POST /v1/entities/{eid}/campaigns；POST .../campaigns/{id}:start/:complete | 周期评估 |
| 报告 | GET/POST /v1/entities/{eid}/reports；GET .../reports/{id}/export | 保留 + 按 entity |
| 通报 | GET/POST /v1/entities/{eid}/notices；POST .../notices/{id}/receipt | 保留 + 按 entity |
| 辖区聚合 | GET /v1/portfolio/summary；GET /v1/portfolio/compare | 跨单位聚合（显式） |
| AI | GET/POST /v1/agent/runs；GET /v1/agent/runs/{id}/trace；GET/POST /v1/evals | 新增 |
| 审计 | GET /v1/audit；GET /v1/audit/{id} | 新增 |
| 系统 | GET /healthz；GET /readyz；GET /metrics | 新增 |

**MCP 工具分级**：
- readonly：search_assets、get_asset、graph_paths、list_findings、get_evidence、knowledge_search；
- controlled：create_case_draft、add_note、request_scan、generate_report_draft；
- dangerous：scan_active、notify_external、delete_asset、close_finding（必须人工触发 + confirmation）。

## 附录 C：核心表 DDL 草图

~~~sql
-- 被监管单位（数据域）
CREATE TABLE regulated_entities (
  id text PRIMARY KEY,
  name text NOT NULL,
  short text,
  region text,
  industry text,
  level text,
  contact text,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 授权与确认
CREATE TABLE scopes (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  name text NOT NULL,
  domains text[] NOT NULL DEFAULT '{}',
  cidrs text[] NOT NULL DEFAULT '{}',
  ports int[] NOT NULL DEFAULT '{}',
  excludes text[] NOT NULL DEFAULT '{}',
  valid_from timestamptz NOT NULL,
  valid_to timestamptz NOT NULL,
  time_window text,
  rate_limit int NOT NULL DEFAULT 0,
  intrusive_allowed boolean NOT NULL DEFAULT false,
  second_auth_required boolean NOT NULL DEFAULT false,
  document_ref text,
  document_hash text,
  signer text,
  state text NOT NULL DEFAULT 'draft',
  CONSTRAINT scopes_state CHECK (state IN ('draft','active','expired','revoked','suspended'))
);

CREATE TABLE confirmations (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  action text NOT NULL,
  resource text NOT NULL,
  operator_id text NOT NULL,
  method text NOT NULL, -- passkey|otp|password|dual_channel
  channel text,
  reason text NOT NULL,
  scope_hash text,
  before_hash text,
  ts timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX ON confirmations (entity_id, action, ts DESC);

-- 资产身份
CREATE TABLE assets_v2 (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  kind text NOT NULL,
  canonical_key text NOT NULL,
  display_name text NOT NULL,
  state text NOT NULL DEFAULT 'candidate',
  confidence numeric(4,3) NOT NULL DEFAULT 0.5,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  owner_id text,
  business_system_id text,
  criticality text NOT NULL DEFAULT 'unknown',
  in_scope boolean NOT NULL DEFAULT false,
  sources text[] NOT NULL DEFAULT '{}',
  attributes jsonb NOT NULL DEFAULT '{}',
  UNIQUE (entity_id, kind, canonical_key)
);

CREATE TABLE asset_aliases (
  asset_id text NOT NULL REFERENCES assets_v2(id),
  alias_key text NOT NULL,
  alias_type text NOT NULL,
  source text,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (asset_id, alias_key)
);

CREATE TABLE asset_observations (
  id bigserial PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  asset_key text NOT NULL,
  source_id text NOT NULL,
  observed_at timestamptz NOT NULL,
  raw_ref text,
  payload_hash text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON asset_observations (entity_id, asset_key, observed_at DESC);

CREATE TABLE relationships (
  id bigserial PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  from_asset_id text NOT NULL REFERENCES assets_v2(id),
  to_asset_id text NOT NULL REFERENCES assets_v2(id),
  type text NOT NULL,
  confidence numeric(4,3) NOT NULL DEFAULT 1.0,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_to timestamptz,
  source_id text,
  evidence_ref text,
  attributes jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON relationships (entity_id, from_asset_id, type);
CREATE INDEX ON relationships (entity_id, to_asset_id, type);

-- 发现与处置
CREATE TABLE findings (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  asset_id text NOT NULL REFERENCES assets_v2(id),
  type text NOT NULL,
  title text NOT NULL,
  lifecycle text NOT NULL DEFAULT 'new',
  severity text NOT NULL,
  confidence numeric(4,3) NOT NULL DEFAULT 0.5,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  source text NOT NULL,
  rule_id text,
  evidence_refs text[] NOT NULL DEFAULT '{}',
  risk_assessment_id text,
  remediation_case_id text,
  CONSTRAINT findings_lifecycle CHECK (lifecycle IN
    ('new','triaged','validating','confirmed','remediating','verified','closed',
     'false_positive','risk_accepted','duplicate'))
);

CREATE TABLE remediation_cases (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  finding_id text NOT NULL REFERENCES findings(id),
  owner_id text,
  priority text NOT NULL,
  state text NOT NULL DEFAULT 'open',
  sla_due timestamptz,
  risk_accept_reason text,
  risk_accept_confirmation_id text,
  risk_accept_expires timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 执行与事件
CREATE TABLE jobs (
  id text PRIMARY KEY,
  entity_id text NOT NULL REFERENCES regulated_entities(id),
  kind text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  state text NOT NULL DEFAULT 'queued',
  priority int NOT NULL DEFAULT 0,
  scope_id text,
  confirmation_id text,
  requested_by text,
  idempotency_key text NOT NULL UNIQUE,
  lease_owner text,
  lease_until timestamptz,
  heartbeat_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 3,
  next_run_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  result_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX ON jobs (state, next_run_at);

CREATE TABLE outbox_events (
  id bigserial PRIMARY KEY,
  entity_id text,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  occurred_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  last_error text,
  dedupe_key text NOT NULL UNIQUE
);

-- AI 轨迹
CREATE TABLE agent_runs (
  id text PRIMARY KEY,
  entity_id text REFERENCES regulated_entities(id),
  case_id text,
  operator_id text NOT NULL,
  model text NOT NULL,
  prompt_version text NOT NULL,
  state text NOT NULL DEFAULT 'running',
  steps int NOT NULL DEFAULT 0,
  tokens_in int NOT NULL DEFAULT 0,
  tokens_out int NOT NULL DEFAULT 0,
  cost_usd numeric(12,6) NOT NULL DEFAULT 0,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);

CREATE TABLE agent_tool_calls (
  id bigserial PRIMARY KEY,
  run_id text NOT NULL REFERENCES agent_runs(id),
  tool text NOT NULL,
  risk_level text NOT NULL,
  input jsonb NOT NULL DEFAULT '{}',
  output jsonb,
  allowed boolean NOT NULL,
  confirmation_id text,
  ts timestamptz NOT NULL DEFAULT now()
);
~~~

## 附录 D：Phase 0/1 任务清单（可执行）

**已完成（2026-10-19）**：第一批：保存 WIP patch；回滚到绿色基线；/v1/entities 一等别名；EASM_SINGLE_USER=1；confirmations 包 + 表（024）+ 端点；regulated_entities 视图（023）；前端 live 层切 /v1/entities。第二批：internal/config；internal/app.Deps；cmd/migrate + schema_migrations；OpenAPI 生成/覆盖校验；CI 四门禁；OIDC（RS256/JWKS）；break-glass；passkey（ES256 challenge-response）。go build/go vet/go test（含 app-role PG 集成）/trace-check/live-smoke 全绿；README/AGENTS/CHANGELOG 同步。

**Phase 1 已完成**：inventory（资产/别名/观察）、Finding 生命周期、Job Queue、Connector 框架（seed/ct）、discovery worker、迁移 025–027、API 与 PG 集成。

**Phase 2 已完成**：DNS/ASM Connector、Finding 自动生成（classify 22 规则）、Finding→ledger 投影、资产状态机、Finding 告警、前端资产/发现/告警实时表、迁移 028–029。

**Phase 3 已完成**：告警通知通道（notify 三闸门）、Finding 批量 confirm/close/project、资产自动衰减（jobworker + HTTP）、cloud Connector、前端筛选/分页/投影/推送/报告入口。

**仍待**：完整 WebAuthn（当前 passkey 为 ES256 step-up，Provider 可替换）、生产 IdP 联调与 JWKS 轮换演练、前端确认/step-up 面板、ASM 厂商字段映射、云厂商原生 API、告警模板/重试策略、批量操作审计汇总、衰减策略按资产类型分级、报表按 Finding 维度聚合。


| # | 任务 | 产出 | 估算 |
| --- | --- | --- | --- |
| 1 | 拍板 A/B；记录 ADR | 决策记录 | 0.5d |
| 2 | 保存当前 diff 为 patch/分支 | 备份 | 0.5d |
| 3 | 修 httpapi：去 tenant 参数、补 Server 字段、统一 handler | 编译通过 | 3d |
| 4 | 修 pgstore：去 withTenant、列/参数对齐 | 编译通过 | 3d |
| 5 | 修测试：去 tenant fixture、重写 entity/确认用例 | 测试通过 | 3d |
| 6 | 迁移 023：regulated_entities + entity_id + RLS | 可迁移 | 1.5d |
| 7 | 前端去 /v1/tenants；加单位切换器 | 前端可用 | 1.5d |
| 8 | 文档同步（AGENTS/README/CHANGELOG） | 口径一致 | 0.5d |
| 9 | config 包 + 启动校验 | 配置收敛 | 1d |
| 10 | 组装根 App/Deps 重构 | 可测试 | 1d |
| 11 | HTTP 超时/优雅停机/安全头/body limit | 运维基线 | 0.5d |
| 12 | /healthz + /readyz + metrics 骨架 | 可观测 | 1d |
| 13 | 迁移工具 + schema_migrations | 可升级 | 1d |
| 14 | OpenAPI 骨架（80% 路由） | 契约 | 2d |
| 15 | CI 四门禁（build/test/migration/openapi） | 防回归 | 0.5d |
| 16 | 单用户认证 + 重认证 + confirmation 表 | 安全基线 | 2d |
| 17 | break-glass + 审计链 | 连续性 | 1d |
| 18 | live-smoke 改双守卫 | 前端回归 | 0.5d |
| 19 | 集成测试跑通（真 PG） | 质量基线 | 1d |
| 20 | 回顾 + 更新路线图 | 进入 Phase 1 | 0.5d |

> 合计约 24 人日；1–2 名工程师约 4 周。关键是**不要边修边加新功能**。

## 附录 E：术语表

| 术语 | 含义 |
| --- | --- |
| EASM | External Attack Surface Management，外部攻击面管理 |
| ASM | Attack Surface Management，攻击面管理（常与 EASM 混用） |
| Exposure Graph | 暴露图：实体 + 关系的图模型，表达攻击面 |
| Canonical Asset | 规范资产：去重合并后的唯一实体 |
| Observation | 观察：来自某个来源的一次原始观测 |
| Finding | 发现：可验证的暴露结论 |
| Case | 处置案件：从发现到闭环的容器 |
| Scope | 授权范围：能看/能打什么 |
| Confirmation | 确认：单用户高危动作的自我确认记录 |
| Outbox | 事务性发件箱：保证事件与状态一致 |
| Idempotency Key | 幂等键：重复请求/任务只生效一次 |
| Tool Gateway | 工具网关：AI/用户调用平台能力的唯一入口 |
| RAG | 检索增强生成：先检索证据再生成 |
| HITL | Human-in-the-loop，人在环 |
| SLO/SLI | 服务目标/指标 |
| MTTR | 平均修复时间 |
| SoD | Separation of Duties，职责分离 |
| 被监管单位 | Regulated Entity；辖区内的监管对象，是数据域而非 SaaS 租户 |
| 单用户模式 | 一个 Operator 主账号；没有 RBAC 矩阵，用能力开关 + 确认 + 审计补偿 |
| 重认证 | 高危动作前再次验证 passkey/OTP/密码 |
| 双通道确认 | 同时通过两个通道确认（如 passkey + 邮件/OTP） |
| 冷却期 | 破坏性动作执行前的可取消等待窗口 |
| Break-glass | 离线恢复凭据；使用即告警 + 审计 + 复盘 |
| Confirmation | 单用户的高危动作确认记录（方式/理由/范围哈希/时间） |
| 辖区组合 | Portfolio；辖区被监管单位的集合与对比视图 |
| 数据域 | entity_id 标识的数据分区；不是用户权限边界 |

---

## 附录 F：与现有需求/增强项的映射

| 现有编号 | 本方案对应 | 说明 |
| --- | --- | --- |
| F2 / FR-DSC | Campaign 模板 + Discovery/Detection | 五阶段降为模板；发现能力独立 |
| F3 / FR-AST | Asset/Alias/Observation | 资产身份与生命周期 |
| F4 / FR-LGR | Finding + Ledger 投影 + Case | 台账解耦 |
| F6 / FR-CLS | Detection 规则 | 22 条规则保留 |
| F7 / FR-CHN | Discovery/Detection Connector | 代码/文档/社交/暗网 |
| F8 / FR-GPH/FR-MIN | Exposure Graph + Risk | 图与四因子 |
| F10/F16/F18 | AI Operating Layer | Agent/Tool Gateway/Eval |
| F11 / FR-RPT | Campaign & Reporting | 报告中心 |
| F12 / IR | OpenAPI + MCP | 契约化 |
| F13 / FR-TEN | Regulated Entity & Scope | 被监管单位数据域 + 授权范围 |
| F14 / FR-MON | Scheduler + Event | 持续监测 |
| F15 / CR | Notice + Confirmation | 通报与确认 |
| F17 / NFR-SEC | Operator & Audit | 单用户身份/确认/审计 |
| ENH-01 | Job Queue/Temporal | 编排接缝 |
| ENH-02 | Graph Provider | Neo4j 可选 |
| ENH-03 | AI Provider/Runtime | 模型可替换 |
| ENH-07 | OIDC | 身份 |
| ENH-08 | Scanner Plugins | 工具执行 |
| ENH-10 | Sandbox/Verifier | 复测 |

---

## 结语

当前项目最宝贵的不是已经写了多少功能，而是已经形成了一套**「不造假」的工程文化**：证据、门禁、状态机、fail-loud、诚实边界、变异测试。这套文化是 EASM 平台最稀缺的资产。

在「监管单位单用户」的新形态下，下一步不是继续堆功能，而是做四件事：

1. **把系统拉回绿色**：先可构建、可测试、可部署，再谈演进。
2. **把主干换对**：从「五阶段流水线」换成「持续 EASM 运营环」，让发现、身份、图、验证、处置成为一等能力。
3. **把数据域划清**：用 regulated_entities + entity_id + RLS 管住辖区多家单位，单用户切换但不串域。
4. **把单用户安全补上**：重认证、双通道、冷却期、break-glass、审计链；承认单用户无法双人复核，用「可追溯的自我确认」替代，并在制度上写明边界。

做到这四点，这个项目才真正配得上「监管单位单用户、AI-native 的 EASM 安全管理平台」这个目标。

---

*本方案为架构建议，不替代 PRD/SRS 的需求裁决；所有涉及外部签字（G8 系列）、真实数据源、生产身份接入的事项，仍按既有治理流程执行，不代签、不静默降级。*
