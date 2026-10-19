package sweep

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（FR-DSC-001 / 一票否决①）：五阶段与步骤数必须逐字对齐工作文件（4/4/5/3/4）。
func TestPhaseModelMatchesWorkFile(t *testing.T) {
	ph := Phases()
	if len(ph) != 5 {
		t.Fatalf("应 5 阶段，实际 %d", len(ph))
	}
	want := map[string]int{"P1": 4, "P2": 4, "P3": 5, "P4": 3, "P5": 4}
	var total int
	for _, p := range ph {
		if n, ok := want[p.ID]; !ok || len(p.Steps) != n {
			t.Errorf("%s 步骤数应为 %d，实际 %d", p.ID, n, len(p.Steps))
		}
		total += len(p.Steps)
		if p.Goal == "" || len(p.Carriers) == 0 || len(p.Outputs) == 0 {
			t.Errorf("%s 属性不完整（DR-03）", p.ID)
		}
	}
	if total != 20 {
		t.Errorf("步骤合计应为 20，实际 %d", total)
	}
}

type memAssets struct {
	mu sync.Mutex
	m  map[string][]asset.Asset
}

func (a *memAssets) ListByTenant(_ context.Context, tenantID string) ([]asset.Asset, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]asset.Asset{}, a.m[tenantID]...), nil
}

func setup() (*Service, *ledger.Service, *memAssets) {
	lg := ledger.NewService(ledger.NewMemStore(), &audit.MemLog{})
	as := &memAssets{m: map[string][]asset.Asset{}}
	svc := NewService(as, classify.New(), lg)
	return svc, lg, as
}

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

func riskyAsset() asset.Asset {
	return asset.Asset{
		ID: "a1", Tenant: "t-a", Name: "backup.hddata.cn", Type: "web", TypeLabel: "网站",
		Risk: "high", Exp: 70, Owner: "运维部", Found: time.Now().UTC(),
		Status: "在用", Beian: "已备案", Source: "P3/Dirsearch", Biz: "备份系统",
		IP: "192.168.1.7", Ports: []int{6379, 3389}, Tech: []string{"nginx/1.18.0"},
	}
}

// 为什么（FR-DSC-002 / F2-AC3）：阶段执行必须做真实判定（classify 确定性检测），
// 命中自动生成台账条目且覆盖度上升——「执行完问题自动入账」是产品主线。
func TestExecuteDetectsAndCreatesLedger(t *testing.T) {
	svc, lg, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	ctx := context.Background()
	sw, err := svc.Execute(ctx, admin(), "req-1", "t-a", []string{"P3"})
	if err != nil {
		t.Fatal(err)
	}
	if sw.Status != StatusDone {
		t.Fatalf("应 done，实际 %s", sw.Status)
	}
	items, _ := lg.List(ctx, admin(), "l", ledger.Filter{Tenant: "t-a"})
	if len(items) == 0 {
		t.Fatal("内网IP+高危端口应产生台账条目")
	}
	// 缺陷①回归守卫：findings 必须等于实际入账（去重后）条目数。
	// 双重计数缺陷会使每步骤累加阶段累计值 → findings(15) ≠ items(3)。
	if sw.Findings != len(items) {
		t.Errorf("findings 应等于去重入账条目数（缺陷①回归）：%d ≠ %d", sw.Findings, len(items))
	}
	stepSum := 0
	for _, st := range sw.Steps {
		stepSum += st.NewIssues
	}
	if stepSum != sw.Findings {
		t.Errorf("各步骤新增之和应等于 findings：%d ≠ %d（步骤级增量口径）", stepSum, sw.Findings)
	}
	var rules []string
	for _, it := range items {
		if it.Phase != "P3" { // 阶段归属 = 资产来源阶段（P3/Dirsearch）
			t.Errorf("条目阶段应为 P3（来源推定），实际 %s", it.Phase)
		}
		if it.Status != ledger.StatusOpen || it.Owner == "" || it.Due.IsZero() {
			t.Errorf("条目必填口径缺失: %+v", it)
		}
		rules = append(rules, it.Title)
	}
	if !strings.Contains(strings.Join(rules, "|"), "6379") {
		t.Errorf("应含 Redis 端口命中: %v", rules)
	}
	// 覆盖度：唯一资产已完成 → 1.0
	cov, _ := svc.Coverage("t-a", "P3")
	if cov != 1.0 {
		t.Errorf("执行后 P3 覆盖度应为 1，实际 %v", cov)
	}
}

// 为什么（幂等/FR-GPH-003 同语义）：重跑不得复制问题条目——
// 以 (tenant, asset, rule) 为去重键，否则台账被重复问题淹没。
func TestRerunIsIdempotent(t *testing.T) {
	svc, lg, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	ctx := context.Background()
	if _, err := svc.Execute(ctx, admin(), "r1", "t-a", []string{"P3"}); err != nil {
		t.Fatal(err)
	}
	before, _ := lg.List(ctx, admin(), "l", ledger.Filter{Tenant: "t-a"})
	if _, err := svc.Execute(ctx, admin(), "r2", "t-a", []string{"P3"}); err != nil {
		t.Fatal(err)
	}
	after, _ := lg.List(ctx, admin(), "l", ledger.Filter{Tenant: "t-a"})
	if len(before) == 0 || len(after) != len(before) {
		t.Errorf("重跑不得新增条目: %d → %d", len(before), len(after))
	}
}

// 为什么（F2.6 / FR-DSC-005）：进度矩阵 = 客户 × 阶段，数据与台账/覆盖度联动。
func TestMatrixAndFullSweep(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	ctx := context.Background()
	// 全量：P1→P5 顺序
	sw, err := svc.Execute(ctx, admin(), "full", "t-a", PhaseIDs())
	if err != nil || sw.Status != StatusDone {
		t.Fatalf("全量应完成: %v %+v", err, sw)
	}
	if len(sw.Steps) != 20 { // 4+4+5+3+4
		t.Errorf("步骤合计应为 20，实际 %d", len(sw.Steps))
	}
	rows := svc.Matrix([]string{"t-a"})
	if len(rows) != 1 || len(rows[0].Cov) != 5 {
		t.Fatalf("矩阵形状错误: %+v", rows)
	}
	for i, c := range rows[0].Cov {
		if c < 1.0 {
			t.Errorf("阶段 %d 覆盖度应达 1，实际 %v", i, c)
		}
	}
	// P5（暗网渠道）无对应资产 → 覆盖度按"已扫资产/总资产"仍为 1（无跳过语义时诚实为 1）
	total := 0
	for _, f := range rows[0].Found {
		total += f
	}
	if total == 0 {
		t.Error("矩阵发现问题数应联动台账 > 0")
	}
}

// 越权主体不得触发排查（FR-DSC-013 / 一票否决⑥同源边界）。
func TestExecuteRejectsOutOfRange(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	tb := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}}
	if _, err := svc.Execute(context.Background(), tb, "r", "t-a", []string{"P1"}); err != rbac.ErrCrossTenant {
		t.Errorf("跨租户触发应拒绝，实际 %v", err)
	}
}

// 无有效授权的租户不得执行排查（FR-DSC-013 / 一票否决⑥同源闸口）。
func TestExecuteRequiresScope(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	svc.SetScope(denyScope{})
	if _, err := svc.Execute(context.Background(), admin(), "r", "t-a", []string{"P1"}); err == nil {
		t.Error("无有效授权应拒绝执行")
	}
}

type denyScope struct{}

func (denyScope) Validate(context.Context, string) error {
	return errors.New("authz: no scope")
}

// 无资产租户：覆盖度保持 0（诚实口径，不虚报进度）。
func TestEmptyTenantCoverageZero(t *testing.T) {
	svc, _, as := setup()
	as.m["t-e"] = nil
	if _, err := svc.Execute(context.Background(), admin(), "r", "t-e", []string{"P1"}); err != nil {
		t.Fatal(err)
	}
	cov, _ := svc.Coverage("t-e", "P1")
	if cov != 0 {
		t.Errorf("无资产租户覆盖度应为 0，实际 %v", cov)
	}
}

// 为什么（V-5 零误报门1 的生产侧接线）：sweep 是 classify 规则命中的入账主路径，
// 必须把「同轮多规则交叉」这一真实信源结构传给 ledger——否则所有规则命中都只带
// 单源，严重级一律被门1 降级（信号被系统性压低=另一种不诚实）。
func TestSweepSuppliesCrossCheckSources(t *testing.T) {
	svc, lg, as := setup()
	// 该资产同时含 Redis 端口（R-PORT）与备份文件名（R-BACKUP 等）→ 多规则交叉
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	ctx := context.Background()
	if _, err := svc.Execute(ctx, admin(), "req-x", "t-a", []string{"P3"}); err != nil {
		t.Fatal(err)
	}
	items, _ := lg.List(ctx, admin(), "l", ledger.Filter{Tenant: "t-a"})
	multi := 0
	for _, it := range items {
		if len(it.XChk) >= 2 {
			multi++
			continue
		}
		if it.Level == "严重" {
			t.Errorf("单源条目不得保留严重级（门1应已降级）: %+v", it)
		}
	}
	if multi == 0 {
		t.Error("多规则命中的资产应提供 ≥2 个交叉信源（rule:*）")
	}
}

// ---- S-1：编排层令牌桶消费（rate_limit 挂账销账）----

type fakeLimiter struct {
	scope authz.Scope
	ok    bool
	err   error
	calls int
}

func (f *fakeLimiter) Get(context.Context, string) (authz.Scope, bool, error) {
	f.calls++
	return f.scope, f.ok, f.err
}

// 为什么（S-1 销账）：授权书写了限速、系统没做=合同风险（与 time_window 同罪）。
// 编排层对每个资产判定轮之间施加步间最小间隔，并把「本次用了多少限速、等了多久」
// 写到执行行（rate_limit/paced_ms）——审计可复算，不是只写在文档里的承诺。
func TestSweepPacesPerAsset(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset(), riskyAsset2()}
	svc.WithLimiter(&fakeLimiter{scope: authz.Scope{RateLimit: 1000}, ok: true}) // 1ms/资产
	var waits int
	var total time.Duration
	svc.paceFn = func(_ context.Context, d time.Duration) error {
		waits++
		total += d
		return nil
	}
	sw, err := svc.Execute(context.Background(), admin(), "req-pace", "t-a", []string{"P3"})
	if err != nil {
		t.Fatal(err)
	}
	if waits == 0 || total <= 0 {
		t.Errorf("应按资产数施加限速等待: waits=%d total=%v", waits, total)
	}
	if sw.RateLimit != 1000 {
		t.Errorf("执行行应记录消费的限速: %d", sw.RateLimit)
	}
	if sw.PacedMS < 0 {
		t.Errorf("paced_ms 不得为负: %d", sw.PacedMS)
	}
	// 每次执行只读一次 scope（不在资产循环里反复查询授权库）
	if fl := svc.lim.(*fakeLimiter); fl.calls != 1 {
		t.Errorf("scope 应每次执行读一次: %d", fl.calls)
	}
}

// 为什么（live 取证发现，2026-10-18）：pacedMS 曾是 Service 级累计字段，第二轮执行的
// paced_ms 会带上第一轮的等待——跨行污染=执行行取证失真（违反 AX-3 可验证性）。
// 守卫：同一 Service 连跑两轮，各执行行 PacedMS 只含本行等待（虚拟时钟=确定性）。
func TestSweepPacedMSIsPerRun(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	svc.WithLimiter(&fakeLimiter{scope: authz.Scope{RateLimit: 1}, ok: true}) // 1s/判定轮
	clk := time.Unix(0, 0)
	svc.now = func() time.Time { return clk }
	svc.paceFn = func(_ context.Context, d time.Duration) error {
		clk = clk.Add(d) // 虚拟时钟：等待即时推进，无真实睡眠
		return nil
	}
	sw1, err := svc.Execute(context.Background(), admin(), "req-p1", "t-a", []string{"P3"})
	if err != nil {
		t.Fatal(err)
	}
	sw2, err := svc.Execute(context.Background(), admin(), "req-p2", "t-a", []string{"P3"})
	if err != nil {
		t.Fatal(err)
	}
	if sw1.PacedMS <= 0 {
		t.Fatalf("第一轮应有等待留痕: %d", sw1.PacedMS)
	}
	if sw2.PacedMS != sw1.PacedMS {
		t.Errorf("paced_ms 必须 per-run 归属: sw1=%dms sw2=%dms（Service 级累计=跨行污染取证）", sw1.PacedMS, sw2.PacedMS)
	}
}

// 为什么：限速读失败必须上浮——「授权库读不到就当没限速」=悄悄绕过合同（fail loud）。
func TestSweepLimiterErrorSurfaces(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	svc.WithLimiter(&fakeLimiter{err: errors.New("authz down")})
	if _, err := svc.Execute(context.Background(), admin(), "req-lim", "t-a", []string{"P3"}); err == nil {
		t.Error("授权参数读失败必须上浮（不得静默不限速）")
	}
}

// 为什么：未装配 Limiter（dev/单测形态）不得 panic，也不得假装在限速——
// paced_ms=0 与 rate_limit 缺省即「本形态无可调速对象」的诚实表达。
func TestSweepNoLimiterNoPacing(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	svc.paceFn = func(context.Context, time.Duration) error {
		t.Error("未装配 Limiter 不得有限速等待")
		return nil
	}
	sw, err := svc.Execute(context.Background(), admin(), "req-nolim", "t-a", []string{"P3"})
	if err != nil {
		t.Fatal(err)
	}
	if sw.RateLimit != 0 || sw.PacedMS != 0 {
		t.Errorf("无 Limiter 时应为不限速形态: rate=%d paced=%d", sw.RateLimit, sw.PacedMS)
	}
}

// 为什么：ctx 取消必须可中断——限速等待不得变成无法取消的睡眠（否则取消排查要等完整轮）。
func TestSweepPaceRespectsContext(t *testing.T) {
	svc, _, as := setup()
	as.m["t-a"] = []asset.Asset{riskyAsset(), riskyAsset2(), riskyAsset2()}
	svc.WithLimiter(&fakeLimiter{scope: authz.Scope{RateLimit: 1}, ok: true}) // 1s/资产=必然被取消
	ctx, cancel := context.WithCancel(context.Background())
	svc.paceFn = func(c context.Context, _ time.Duration) error {
		cancel() // 首次等待即取消
		<-c.Done()
		return c.Err()
	}
	if _, err := svc.Execute(ctx, admin(), "req-ctx", "t-a", []string{"P3"}); err == nil {
		t.Error("ctx 取消应中断执行")
	}
}

func riskyAsset2() asset.Asset {
	a := riskyAsset()
	a.ID = "a2"
	a.Name = "db.hddata.cn"
	a.IP = "192.168.1.9"
	a.Ports = []int{3306}
	return a
}
