// render.go — 报告确定性渲染（WP-M2-09）：四受众差异化执行摘要 + 八章节 Markdown。
// 所有数字来自 facts 实时聚合，空集必须显式写“本周期 0 项”，禁止静态范文（FR-RPT-002）。
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

var periodLabel = map[string]string{PeriodD7: "近 7 天", PeriodD30: "近 30 天", PeriodQuarter: "本季度"}
var audienceLabel = map[string]string{
	AudExec: "高管 / 董事会", AudOps: "安全运营", AudCompliance: "合规 / 审计", AudRedteam: "红队 / 蓝队",
}

var levelRank = map[string]int{"严重": 0, "高": 1, "中": 2}
var riskRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
var riskLabel = map[string]string{"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "提示"}

// ledgerStatusLabel 台账四态中文（与控制台口径一致）。
var ledgerStatusLabel = map[string]string{
	ledger.StatusOpen: "待整改", ledger.StatusDoing: "整改中", ledger.StatusClosed: "已闭环", ledger.StatusNotify: "待通报",
}

func render(r Report, d facts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s 互联网敏感信息泄露排查报告\n\n", r.TenantName)
	fmt.Fprintf(&b, "- 报告编号：%s\n- 客户：%s（%s）\n- 周期：%s（%s ~ %s）\n- 受众：%s\n- 生成时间：%s\n\n",
		r.ID, r.TenantName, r.Tenant, periodLabel[r.Period],
		r.PeriodFrom.Format("2006-01-02"), r.PeriodTo.Format("2006-01-02"),
		audienceLabel[r.Audience], r.GeneratedAt.Format(time.RFC3339))
	for _, k := range r.Sections {
		switch k {
		case SecExec:
			renderExec(&b, r, d)
		case SecKPI:
			renderKPI(&b, d)
		case SecRisk:
			renderRisk(&b, d)
		case SecPath:
			renderPath(&b, d)
		case SecVuln:
			renderVuln(&b, d)
		case SecIntel:
			renderIntel(&b, d)
		case SecAdvice:
			renderAdvice(&b, d)
		case SecAppendix:
			renderAppendix(&b, d)
		}
	}
	b.WriteString("\n> 本报告由 EASM 平台依据所选客户的风险台账、资产暴露面、暗网线索包、处置工单与线索通报事实实时聚合（数字可复算）。确定性切片（ENH-10 AI 动态内容未触达）。\n")
	return b.String()
}

// ---- 统计原语 ----

type counts struct {
	byLevel  map[string]int
	byCat    map[string]int
	byStatus map[string]int
	byPhase  map[string]int
	open     int // 待整改+整改中
	closed   int
	severe   int // 严重+高
}

func tally(items []ledger.Item) counts {
	c := counts{map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, 0, 0, 0}
	for _, it := range items {
		c.byLevel[it.Level]++
		c.byCat[it.Category]++
		c.byStatus[it.Status]++
		c.byPhase[it.Phase]++
		switch it.Status {
		case ledger.StatusOpen, ledger.StatusDoing, ledger.StatusNotify:
			c.open++
		case ledger.StatusClosed:
			c.closed++
		}
		if it.Level == "严重" || it.Level == "高" {
			c.severe++
		}
	}
	return c
}

func sortItems(items []ledger.Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if levelRank[items[i].Level] != levelRank[items[j].Level] {
			return levelRank[items[i].Level] < levelRank[items[j].Level]
		}
		return items[i].Found.After(items[j].Found)
	})
}

func head(items []ledger.Item, n int) []ledger.Item {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

func joinCount(m map[string]int, keys []string) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, " / ")
}

// ---- ① 执行摘要（四受众首段明显不同；FR-RPT-003）----

func renderExec(b *strings.Builder, r Report, d facts) {
	c := tally(d.items)
	b.WriteString("\n## 一、执行摘要\n\n")
	top := head(sortedCopy(d.items), 3)
	switch r.Audience {
	case AudExec:
		// 决策口径：总体定性 + 经营/监管风险 + 是否需要决策
		verd := "总体可控"
		if c.severe > 0 || c.open > c.closed {
			verd = "存在需要管理层关注的敞口"
		}
		fmt.Fprintf(b, "本期排查覆盖客户 **%s** 资产 %d 项，周期内入账敏感信息风险 %d 项（严重/高 %d），尚未闭环 %d 项、已闭环 %d 项，整体态势**%s**。\n\n",
			r.TenantName, len(d.assets), len(d.items), c.severe, c.open, c.closed, verd)
		fmt.Fprintf(b, "从经营与监管角度，暗网线索包 %d 个、平台处置工单 %d 个、线索通报 %d 次决定了外部扩散面与合规时限压力；建议管理层关注资源投入与对外报送决策。\n",
			len(d.pkgs), len(d.wos), len(d.notices))
	case AudOps:
		// 运营口径：工单量/分布 + 本期要干的活
		fmt.Fprintf(b, "本期 %s 新增/在账风险条目 %d 项，按状态 %s；运营侧待处理（待整改/整改中/待通报）合计 %d 项，已闭环 %d 项。\n\n",
			r.TenantName, len(d.items),
			joinCount(c.byStatus, []string{ledger.StatusOpen, ledger.StatusDoing, ledger.StatusNotify, ledger.StatusClosed}),
			c.open, c.closed)
		fmt.Fprintf(b, "外部处置面：暗网线索包 %d 个、平台工单 %d 个（按五态推进）、线索通报 %d 次；本节给出本期工单与催办的直接工作面。\n",
			len(d.pkgs), len(d.wos), len(d.notices))
	case AudCompliance:
		// 合规口径：法条/通报/时限/留痕
		pending, overdue, submitted := 0, 0, 0
		for _, n := range d.notices {
			switch {
			case n.Status == notice.StatusSubmitted:
				submitted++
			case n.Overdue:
				overdue++
			default:
				pending++
			}
		}
		fmt.Fprintf(b, "按《网络安全法》及属地通报合规口径，%s 本周期台账事实 %d 项（%s），线索通报已报送 %d 次、待报送 %d 次、**超时未报送 %d 次**（公安 24h / 省通报中心 48h 时限，A-08 已显著标识）。\n\n",
			r.TenantName, len(d.items), joinCount(c.byCat, []string{"系统架构类", "代码密码类", "业务经营类"}),
			submitted, pending, overdue)
		fmt.Fprintf(b, "所有通报均有通报单号、材料 SHA-256、发起时间三要素留痕（CR-002），报告正文数字可由台账与通报记录复算，支持审计取证。\n")
	case AudRedteam:
		// 攻防口径：可利用面/路径/最该先打的点
		exposed := highExposureAssets(d.assets)
		fmt.Fprintf(b, "从攻防视角，%s 当前暴露面资产 %d 项（critical/high %d），周期内严重/高台账事实 %d 项；暗网已出现线索包 %d 个，说明部分泄露已进入外部可达阶段。\n\n",
			r.TenantName, len(d.assets), len(exposed), c.severe, len(d.pkgs))
		fmt.Fprintf(b, "本报告攻击路径与情报章节给出可直接用于复验的一跳路径与命中资产，建议红队按严重→高优先级对外部可达载体先行复测。\n")
	}
	if len(top) > 0 {
		b.WriteString("\n本期首要风险（按等级/发现时间取前三）：\n\n")
		for _, it := range top {
			fmt.Fprintf(b, "- [%s] %s（载体 %s，%s，责任 %s，状态 %s）\n",
				it.Level, it.Title, it.Asset, it.Found.Format("2006-01-02"), it.Owner, ledgerStatusLabel[it.Status])
		}
	} else {
		b.WriteString("\n本周期内无入账风险条目（首要风险清单为空，非静态范文）。\n")
	}
}

func sortedCopy(items []ledger.Item) []ledger.Item {
	out := make([]ledger.Item, len(items))
	copy(out, items)
	sortItems(out)
	return out
}

// ---- ② 关键指标 ----

func renderKPI(b *strings.Builder, d facts) {
	c := tally(d.items)
	rate := 0.0
	if len(d.items) > 0 {
		rate = float64(c.closed) * 100 / float64(len(d.items))
	}
	b.WriteString("\n## 二、关键指标（KPI）\n\n")
	fmt.Fprintf(b, "| 指标 | 数值 |\n| --- | --- |\n")
	fmt.Fprintf(b, "| 周期内风险条目 | %d |\n", len(d.items))
	fmt.Fprintf(b, "| 严重 / 高 / 中 | %d / %d / %d |\n", c.byLevel["严重"], c.byLevel["高"], c.byLevel["中"])
	fmt.Fprintf(b, "| 待整改 / 整改中 / 待通报 / 已闭环 | %d / %d / %d / %d |\n",
		c.byStatus[ledger.StatusOpen], c.byStatus[ledger.StatusDoing], c.byStatus[ledger.StatusNotify], c.byStatus[ledger.StatusClosed])
	fmt.Fprintf(b, "| 闭环率 | %.1f%% |\n", rate)
	fmt.Fprintf(b, "| 暴露面资产总数 | %d（critical/high %d） |\n", len(d.assets), len(highExposureAssets(d.assets)))
	fmt.Fprintf(b, "| 暗网线索包 | %d |\n", len(d.pkgs))
	fmt.Fprintf(b, "| 平台处置工单 | %d（未终态 %d） |\n", len(d.wos), openWorkOrders(d.wos))
	fmt.Fprintf(b, "| 线索通报 | %d（已报送 %d / 超时 %d） |\n\n", len(d.notices), submittedNotices(d.notices), overdueNotices(d.notices))
	b.WriteString("按敏感数据分类：\n\n")
	for _, k := range []string{"系统架构类", "代码密码类", "业务经营类"} {
		fmt.Fprintf(b, "- %s：%d 项\n", k, c.byCat[k])
	}
}

// ---- ③ 风险资产清单 ----

func renderRisk(b *strings.Builder, d facts) {
	items := sortedCopy(d.items)
	b.WriteString("\n## 三、风险资产清单\n\n")
	if len(items) == 0 {
		b.WriteString("本周期内无风险条目。\n")
		return
	}
	fmt.Fprintf(b, "共 %d 项（按等级、发现时间排序）：\n\n", len(items))
	b.WriteString("| 等级 | 问题 | 载体 | 分类 | 来源 | 发现日期 | 处置措施 | 责任 | 状态 |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, it := range items {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			it.Level, esc(it.Title), esc(it.Asset), it.Category, it.Source,
			it.Found.Format("2006-01-02"), it.Action, esc(it.Owner), ledgerStatusLabel[it.Status])
	}
}

// ---- ④ 攻击路径推演（确定性一跳；ENH-02 多跳未触达，显式登记）----

func renderPath(b *strings.Builder, d facts) {
	b.WriteString("\n## 四、攻击路径推演\n\n")
	seeds := make([]ledger.Item, 0)
	for _, it := range d.items {
		if (it.Level == "严重" || it.Level == "高") && it.Status != ledger.StatusClosed {
			seeds = append(seeds, it)
		}
	}
	sortItems(seeds)
	if len(seeds) == 0 {
		b.WriteString("本周期无未闭环的严重/高风险事实，未形成可推演路径（不以想象路径填充）。\n")
	} else {
		fmt.Fprintf(b, "以下路径由台账事实与暗网/工单事实实时关联（一跳；多跳图推演 ENH-02 未触达）：\n\n")
		for i, it := range head(seeds, 8) {
			chain := it.Source + " → 敏感信息暴露（" + it.Category + "）→ 载体 " + it.Asset
			if pkgHit := packageFor(d.pkgs, it); pkgHit != "" {
				chain += " → 暗网扩散（线索包 " + pkgHit + "）"
			}
			if wo := workOrderFor(d.wos, it.ID); wo != nil {
				chain += " → 平台处置（" + wo.ID + " " + wo.Status + "）"
			} else {
				chain += " → 尚未建工单（外部处置缺口）"
			}
			fmt.Fprintf(b, "%d. %s\n   - 起点事实：%s（%s，%s）\n", i+1, chain, it.Title, it.ID, it.Level)
		}
	}
}

// packageFor 在线索包条目中查找与台账载体相关的命中（载体名出现在帖子 URL/来源中）。
func packageFor(pkgs []darkweb.LeadPackage, it ledger.Item) string {
	for _, pk := range pkgs {
		for _, li := range pk.Items {
			if (li.PostURL != "" && strings.Contains(li.PostURL, it.Asset)) ||
				(li.Source != "" && strings.Contains(li.Source, it.Asset)) {
				return pk.PackageID
			}
		}
	}
	return ""
}

func workOrderFor(wos []workorder.WorkOrder, ledgerID string) *workorder.WorkOrder {
	for i := range wos {
		if wos[i].LedgerID == ledgerID {
			return &wos[i]
		}
	}
	return nil
}

// ---- ⑤ 漏洞影响面（由台账分类/暴露面资产推得；无外部 CVE 库接入则显式说明口径）----

func renderVuln(b *strings.Builder, d facts) {
	b.WriteString("\n## 五、漏洞影响面\n\n")
	exposed := highExposureAssets(d.assets)
	cred := 0
	for _, it := range d.items {
		if it.Category == "代码密码类" {
			cred++
		}
	}
	fmt.Fprintf(b, "- 代码/密码类泄露事实 %d 项（凭据、密钥、源码类暴露，等价于可直接利用的弱面）；\n", cred)
	fmt.Fprintf(b, "- 高风险暴露面资产（critical/high）%d 项：\n", len(exposed))
	if len(exposed) == 0 {
		b.WriteString("  本期无 critical/high 评级资产。\n")
	} else {
		for _, a := range headAssets(exposed, 10) {
			t := a.TypeLabel
			if t == "" {
				t = a.Type
			}
			fmt.Fprintf(b, "  - %s（%s，风险 %s，曝光度 %d，归属 %s）\n", a.Name, t, riskLabel[a.Risk], a.Exp, a.Owner)
		}
	}
	b.WriteString("\n> 口径说明：本期漏洞影响面由风险台账分类与资产暴露面评级实时聚合；CVE 知识库映射章节随漏洞库租户命中面开放后补齐。\n")
}

// highExposureAssets 筛出 critical/high 评级资产，按风险等级升序、曝光度降序排序。
func highExposureAssets(assets []asset.Asset) []asset.Asset {
	out := make([]asset.Asset, 0)
	for _, a := range assets {
		if a.Risk == "critical" || a.Risk == "high" {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if riskRank[out[i].Risk] != riskRank[out[j].Risk] {
			return riskRank[out[i].Risk] < riskRank[out[j].Risk]
		}
		return out[i].Exp > out[j].Exp
	})
	return out
}

func headAssets(as []asset.Asset, n int) []asset.Asset {
	if len(as) <= n {
		return as
	}
	return as[:n]
}

// ---- ⑥ 情报命中 ----

func renderIntel(b *strings.Builder, d facts) {
	b.WriteString("\n## 六、情报命中\n\n")
	hits := 0
	for _, pk := range d.pkgs {
		hits += len(pk.Items)
	}
	fmt.Fprintf(b, "- 暗网线索包 %d 个，纳入线索明细 %d 条；\n", len(d.pkgs), hits)
	if len(d.pkgs) == 0 {
		b.WriteString("- 本周期无暗网线索命中（IOC 资产命中面随情报库租户视图开放后在本节补充）。\n")
		return
	}
	for _, pk := range d.pkgs {
		gen := pk.GeneratedAt // darkweb.LeadPackage.GeneratedAt 为 RFC3339 字符串
		if len(gen) >= 10 {
			gen = gen[:10]
		}
		fmt.Fprintf(b, "- 线索包 %s（生成 %s，线索 %d 条，量级估计 %d~%d，置信 %.2f）\n",
			pk.PackageID, gen, len(pk.Items),
			pk.Scale.Low, pk.Scale.High, pk.Scale.Confidence)
	}
}

// ---- ⑦ 处置建议与路线图（优先级事实驱动）----

func renderAdvice(b *strings.Builder, d facts) {
	c := tally(d.items)
	b.WriteString("\n## 七、处置建议与路线图\n\n")
	p1, p2, _ := splitRoadmap(d.items)
	fmt.Fprintf(b, "**P1（即时，24h 内）**：未闭环严重/高风险 %d 项", len(p1))
	if overdueNotices(d.notices) > 0 {
		fmt.Fprintf(b, "；**超时未报送 %d 项须立即补报**", overdueNotices(d.notices))
	}
	b.WriteString("。\n")
	for _, it := range head(p1, 5) {
		fmt.Fprintf(b, "- %s：%s（措施 %s，责任 %s，时限 %s）\n", it.ID, it.Title, it.Action, it.Owner, it.Due.Format("2006-01-02"))
	}
	fmt.Fprintf(b, "\n**P2（1–2 周）**：中危与整改中条目 %d 项，推进七类措施矩阵落地并复测验证（闭环禁止造假）。\n", len(p2))
	fmt.Fprintf(b, "\n**P3（持续）**：已闭环 %d 项纳入常态监测；暗网巡查、线索包与平台工单五态跟踪持续运行（线索包 %d / 工单 %d / 通报 %d）。\n",
		c.closed, len(d.pkgs), len(d.wos), len(d.notices))
}

func splitRoadmap(items []ledger.Item) (p1, p2, p3 []ledger.Item) {
	for _, it := range items {
		switch {
		case (it.Level == "严重" || it.Level == "高") && it.Status != ledger.StatusClosed:
			p1 = append(p1, it)
		case it.Status == ledger.StatusClosed:
			p3 = append(p3, it)
		default:
			p2 = append(p2, it)
		}
	}
	sortItems(p1)
	return
}

// ---- ⑧ 附录：数据源与覆盖 ----

func renderAppendix(b *strings.Builder, d facts) {
	c := tally(d.items)
	b.WriteString("\n## 八、附录：数据源与覆盖\n\n")
	b.WriteString("本报告数据全部取自平台实时事实源：\n\n")
	fmt.Fprintf(b, "| 数据源 | 本期记录数 | 用途章节 |\n| --- | --- | --- |\n")
	fmt.Fprintf(b, "| 风险台账（周期内） | %d | KPI/风险清单/路径/建议 |\n", len(d.items))
	fmt.Fprintf(b, "| 资产暴露面 | %d | KPI/漏洞影响面 |\n", len(d.assets))
	fmt.Fprintf(b, "| 暗网线索包 | %d | 路径/情报命中 |\n", len(d.pkgs))
	fmt.Fprintf(b, "| 平台处置工单 | %d | 路径/KPI/建议 |\n", len(d.wos))
	fmt.Fprintf(b, "| 线索通报 | %d | 执行摘要/KPI/建议 |\n\n", len(d.notices))
	b.WriteString("阶段覆盖（台账 P1–P5）：\n\n")
	for _, ph := range []string{"P1", "P2", "P3", "P4", "P5"} {
		fmt.Fprintf(b, "- %s：%d 项\n", ph, c.byPhase[ph])
	}
	b.WriteString("\n复算方式：对同一租户/周期/受众/章节组合重新生成，正文与内容哈希应可复现（事实未变时）。\n")
}

// ---- 工单/通报统计辅助 ----

func openWorkOrders(wos []workorder.WorkOrder) int {
	n := 0
	for _, w := range wos {
		if w.Status != workorder.StatusResolved {
			n++
		}
	}
	return n
}

func submittedNotices(ns []notice.Notice) int {
	n := 0
	for _, x := range ns {
		if x.Status == notice.StatusSubmitted {
			n++
		}
	}
	return n
}

func overdueNotices(ns []notice.Notice) int {
	n := 0
	for _, x := range ns {
		if x.Overdue {
			n++
		}
	}
	return n
}

func esc(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
