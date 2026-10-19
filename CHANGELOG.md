# Changelog

本仓库采用 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 格式，版本遵循语义化版本（[SemVer](https://semver.org/lang/zh-CN/)）。

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
