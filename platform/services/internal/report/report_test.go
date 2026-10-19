package report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

// 租户作用域主体（R3 只读且仅 t-a）：用于验证越权闸必须先于任何读数发生。
func scopedTA() rbac.Principal {
	return rbac.Principal{UserID: "u3", Role: "R3", TenantIDs: []string{"t-a"}}
}

// ---- fakes ----

type fakeTenants struct{ m map[string]tenant.Tenant }

func (f fakeTenants) Get(_ context.Context, _ rbac.Principal, _, id string) (tenant.Tenant, error) {
	if t, ok := f.m[id]; ok {
		return t, nil
	}
	return tenant.Tenant{}, tenant.ErrNotFound
}

type fakeLedger struct{ items []ledger.Item }

func (f fakeLedger) List(_ context.Context, _ rbac.Principal, _ string, fl ledger.Filter) ([]ledger.Item, error) {
	out := make([]ledger.Item, 0)
	for _, it := range f.items {
		if fl.Tenant == "" || it.Tenant == fl.Tenant {
			out = append(out, it)
		}
	}
	return out, nil
}

type fakeAssets struct{ m map[string][]asset.Asset }

func (f fakeAssets) ListByTenant(_ context.Context, _ rbac.Principal, _, id string) ([]asset.Asset, error) {
	return f.m[id], nil
}

type fakePkgs struct {
	m map[string][]darkweb.LeadPackage
}

func (f fakePkgs) ListPackages(_ context.Context, id string) ([]darkweb.LeadPackage, error) {
	return f.m[id], nil
}

type fakeWOs struct {
	m map[string][]workorder.WorkOrder
}

func (f fakeWOs) List(_ context.Context, _ rbac.Principal, _, id, _ string) ([]workorder.WorkOrder, error) {
	return f.m[id], nil
}

type fakeNotices struct{ m map[string][]notice.Notice }

func (f fakeNotices) List(_ context.Context, _ rbac.Principal, _, id, _ string) ([]notice.Notice, error) {
	return f.m[id], nil
}

// ---- 装配 ----

var fixedNow = time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC)

func ledItem(id, ten string, found time.Time, level string) ledger.Item {
	return ledger.Item{ID: id, Tenant: ten, Phase: "P4", Category: "代码密码类",
		Asset: "github.com/" + ten + "/" + id, Title: "仓库泄露 " + id, Level: level,
		Source: "EXT-1/gitleaks", Found: found, Action: "删除", Owner: "安全运营",
		Due: found.AddDate(0, 0, 1), Status: ledger.StatusOpen}
}

// newSvc 装配固定事实（台账/线索日期锚定 fixedNow），时钟由 now 独立注入——
// 这样把时钟拨到远离事实的日期即可构造「空窗口」（条目不随时钟漂移）。
func newSvc(now time.Time) *Service {
	tens := fakeTenants{m: map[string]tenant.Tenant{
		"t-a": {ID: "t-a", Name: "甲客户"},
		"t-b": {ID: "t-b", Name: "乙客户"},
	}}
	led := fakeLedger{items: []ledger.Item{
		ledItem("L-old", "t-a", fixedNow.AddDate(0, 0, -40), "中"), // 近 7/30 天窗口外
		ledItem("L-7", "t-a", fixedNow.AddDate(0, 0, -3), "严重"),
		ledItem("L-30", "t-a", fixedNow.AddDate(0, 0, -20), "高"),
		ledItem("L-b", "t-b", fixedNow.AddDate(0, 0, -2), "严重"), // 另一租户
	}}
	asts := fakeAssets{m: map[string][]asset.Asset{
		"t-a": {{ID: "A-1", Tenant: "t-a", Name: "api.t-a", Type: "domain", Risk: "critical", Exp: 90, Owner: "运维"}},
		"t-b": {{ID: "A-2", Tenant: "t-b", Name: "api.t-b", Type: "domain", Risk: "high", Exp: 50, Owner: "运维"}},
	}}
	pkgs := fakePkgs{m: map[string][]darkweb.LeadPackage{
		"t-a": {{PackageID: "NB-PKG-A", TenantID: "t-a", GeneratedAt: "2026-10-16T01:02:03Z",
			Items: []darkweb.LeadItem{{SampleID: "S-1", Source: "暗网论坛", PostURL: "https://forum/x?github.com/t-a/L-7", Confidence: 0.91}}}},
	}}
	wos := fakeWOs{m: map[string][]workorder.WorkOrder{
		"t-a": {{ID: "WO-1", Tenant: "t-a", LedgerID: "L-7", Status: workorder.StatusPending}},
	}}
	nots := fakeNotices{m: map[string][]notice.Notice{
		"t-a": {{ID: "NB-1", Tenant: "t-a", LedgerID: "L-7", Target: notice.TargetPolice,
			Status: notice.StatusPending, DeadlineH: 24, CreatedAt: fixedNow.Add(-72 * time.Hour), Overdue: true}},
	}}
	s := NewService(NewMemStore(), &audit.MemLog{}, tens, led)
	s.WithAssets(asts)
	s.WithPackages(pkgs)
	s.WithWorkOrders(wos)
	s.WithNotices(nots)
	s.now = func() time.Time { return now }
	return s
}

func baseParams(tenant string) Params {
	return Params{Tenant: tenant, Period: PeriodD7, Audience: AudExec}
}

// 为什么（FR-RPT-002 + A-05）：报告数字必须来自实时台账且按周期窗口裁剪——
// 若 gather 不再裁剪窗口，窗外的 L-old 会被计入 d7（2→3），本测试必须失败。
func TestGenerateWindowFiltersLedgerItems(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	r7, err := s.Generate(ctx, admin(), "r", baseParams("t-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r7.Text, "周期内风险条目 | 1") {
		t.Errorf("d7 应只含窗口内 1 项（L-7），正文未体现：\n%s", r7.Text)
	}
	if strings.Contains(r7.Text, "L-old") {
		t.Errorf("窗外 40 天的 L-old 不得出现在 d7 报告中")
	}
	// d30 应纳入 L-30（2 项），但仍排除 L-old
	p30 := baseParams("t-a")
	p30.Period = PeriodD30
	r30, err := s.Generate(ctx, admin(), "r", p30)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r30.Text, "周期内风险条目 | 2") {
		t.Errorf("d30 应含 2 项（L-7/L-30）：\n%s", r30.Text)
	}
}

// 为什么（FR-RPT-003 验收硬条件）：四受众执行摘要首段必须明显不同——
// 渲染器一旦退化为统一范文，四者首段相同，本测试失败。
func TestAudiencesFirstParagraphsDiffer(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	first := map[string]string{}
	for _, a := range []string{AudExec, AudOps, AudCompliance, AudRedteam} {
		p := baseParams("t-a")
		p.Audience = a
		r, err := s.Generate(ctx, admin(), "r", p)
		if err != nil {
			t.Fatal(err)
		}
		i := strings.Index(r.Text, "## 一、执行摘要")
		seg := r.Text[i:]
		first[a] = seg
	}
	for _, x := range []string{AudExec, AudOps, AudCompliance, AudRedteam} {
		for _, y := range []string{AudExec, AudOps, AudCompliance, AudRedteam} {
			if x < y && first[x] == first[y] {
				t.Errorf("受众 %s 与 %s 执行摘要完全相同（FR-RPT-003 要求明显不同）", x, y)
			}
		}
	}
	if !strings.Contains(first[AudCompliance], "超时未报送 1 次") {
		t.Errorf("合规受众须显式呈现超时未报送计数：\n%s", first[AudCompliance])
	}
}

// 为什么（A-05「切客户全变」）：报告所有事实按租户隔离——
// 若 gather 漏掉任何一个租户过滤（读了全量），t-b 报告会混入 t-a 的载体/线索包，A-05 破。
func TestSwitchingTenantChangesAllFacts(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	ra, err := s.Generate(ctx, admin(), "r", baseParams("t-a"))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := s.Generate(ctx, admin(), "r", baseParams("t-b"))
	if err != nil {
		t.Fatal(err)
	}
	if ra.Text == rb.Text || ra.ID == rb.ID {
		t.Fatalf("切客户后正文与编号都必须变化：%s / %s", ra.ID, rb.ID)
	}
	if !strings.Contains(rb.Text, "乙客户") || strings.Contains(rb.Text, "L-7") || strings.Contains(rb.Text, "NB-PKG-A") {
		t.Errorf("t-b 报告不得混入 t-a 事实：\n%s", rb.Text)
	}
	if !strings.Contains(ra.Text, "github.com/t-a/L-7") || !strings.Contains(ra.Text, "NB-PKG-A") {
		t.Errorf("t-a 报告应含自身载体与线索包：\n%s", ra.Text)
	}
}

// 为什么（章节参数化 + 未知章节必须拒绝）：章节选择是 FR-RPT-001 输入契约，
// 未知键静默忽略会让前端拿到缺章却以为全量的报告（fail loud）。
func TestSectionsSelectionAndRejectUnknown(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	p := baseParams("t-a")
	p.Sections = []string{SecKPI, SecKPI, SecRisk} // 含重复
	r, err := s.Generate(ctx, admin(), "r", p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Text, "执行摘要") || !strings.Contains(r.Text, "关键指标") || !strings.Contains(r.Text, "风险资产清单") {
		t.Errorf("仅应渲染 kpi/risk（去重）：%v", r.Sections)
	}
	if len(r.Sections) != 2 {
		t.Errorf("章节应去重为 2，实际 %v", r.Sections)
	}
	bad := baseParams("t-a")
	bad.Sections = []string{"kpi", "bogus"}
	if _, err := s.Generate(ctx, admin(), "r", bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("未知章节应 ErrInvalid，实际 %v", err)
	}
}

// 为什么（同参数同窗口编号幂等）：历史记录按参数组合保存，重复生成应覆盖刷新而非堆两条；
// 换章节/周期=新组合=新编号。
func TestIDDeterministicPerParamsAndHistoryIsolation(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	r1, err := s.Generate(ctx, admin(), "r", baseParams("t-a"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Generate(ctx, admin(), "r", baseParams("t-a"))
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID != r2.ID || !strings.HasPrefix(r1.ID, "RPT-") {
		t.Errorf("同参同窗编号应幂等：%s / %s", r1.ID, r2.ID)
	}
	if r1.ContentHash == "" || len(r1.ContentHash) != 64 || r1.ContentHash != r2.ContentHash {
		t.Errorf("内容哈希应存在且可复算：%q/%q", r1.ContentHash, r2.ContentHash)
	}
	listA, _ := s.List(ctx, admin(), "r", "t-a")
	if len(listA) != 1 {
		t.Errorf("覆盖刷新后 t-a 历史应 1 条，实际 %d", len(listA))
	}
	// 生成 t-b 后 t-a 历史不被污染（行级租户隔离）
	if _, err := s.Generate(ctx, admin(), "r", baseParams("t-b")); err != nil {
		t.Fatal(err)
	}
	listA2, _ := s.List(ctx, admin(), "r", "t-a")
	if len(listA2) != 1 || listA2[0].Tenant != "t-a" {
		t.Errorf("t-a 历史被 t-b 污染：%+v", listA2)
	}
	if _, err := s.Get(ctx, admin(), "r", "t-a", r1.ID); err != nil {
		t.Errorf("同租户应可读自身报告：%v", err)
	}
	if _, err := s.Get(ctx, admin(), "r", "t-b", r1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("跨租户读报告必须 ErrNotFound，实际 %v", err)
	}
}

// 为什么（闸必须先于读数）：无权限/越租户/未知租户都不得产出报告。
func TestGuardsDenyBeforeAnyData(t *testing.T) {
	s := newSvc(fixedNow)
	ctx := context.Background()
	// R3(t-a) 尝试 t-b：InScope 拒绝
	if _, err := s.Generate(ctx, scopedTA(), "r", baseParams("t-b")); !errors.Is(err, rbac.ErrCrossTenant) {
		t.Errorf("跨租户应 ErrCrossTenant，实际 %v", err)
	}
	// 未知租户：tenant.Get 失败
	if _, err := s.Generate(ctx, admin(), "r", baseParams("nope")); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("未知租户应 tenant.ErrNotFound，实际 %v", err)
	}
	// 非法 period/audience
	bad := baseParams("t-a")
	bad.Period = "year"
	if _, err := s.Generate(ctx, admin(), "r", bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("非法周期应 ErrInvalid，实际 %v", err)
	}
}

// 为什么（FR-RPT-002 禁止静态范文）：空窗口必须显式写 0 项，而不是输出预制模板。
func TestEmptyWindowStatesZeroExplicitly(t *testing.T) {
	s := newSvc(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) // 所有 fixture 条目都在窗外
	p := baseParams("t-a")
	r, err := s.Generate(context.Background(), admin(), "r", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Text, "周期内风险条目 | 0") {
		t.Errorf("空窗口 KPI 必须显式 0：\n%s", r.Text)
	}
	if !strings.Contains(r.Text, "本周期内无入账风险条目") {
		t.Errorf("空窗口执行摘要须显式声明无条目（非静态范文兜底）：\n%s", r.Text)
	}
}
