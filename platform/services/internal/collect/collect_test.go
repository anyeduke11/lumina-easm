package collect

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（M2-01 全链 = 授权闸→子进程→契约→台账+证据，四件套联动的首个闭环）：
// 扫描必须在 authz.Validate（有效期+时间窗）之后执行——窗口消费缺口由此真正接到
// 执行路径上；候选经 candidate 闸入台账且**重扫不翻倍**（去重键=tenant|file|rule|line）；
// 报告原文进证据库回填 snapshot_ref（C-5 回溯）。exec 注入假执行器，CI 无 binary 依赖。

type fakeGate struct{ err error }

func (f fakeGate) Validate(context.Context, string) error { return f.err }
func (f fakeGate) CheckTarget(context.Context, rbac.Principal, string, string, string, int) error {
	return f.err
}
func (f fakeGate) RequireSecondAuth(context.Context, string) error { return f.err }

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

func newSvc(t *testing.T, gateErr error) (*Service, *ledger.Service, *candidate.Service) {
	t.Helper()
	l := &audit.MemLog{}
	led := ledger.NewService(ledger.NewMemStore(), l)
	cands := candidate.NewService()
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(cands, led, fakeGate{gateErr}, ev,
		func(ctx context.Context, bin string, args []string) error {
			// 假执行器：模拟 gitleaks 写 report-path（末位参数）
			rp := args[len(args)-1]
			return os.WriteFile(rp, []byte(sampleReport()), 0o600)
		})
	return s, led, cands
}

func TestScanRepoFullChain(t *testing.T) {
	s, led, cands := newSvc(t, nil)
	ctx := context.Background()
	res, err := s.ScanRepo(ctx, admin(), "r1", "t-a", t.TempDir(), "安全运营")
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 2 || res.Unsupported != 0 || res.NewLedger != 2 {
		t.Fatalf("首扫应 accepted=2/new=2，实际 %+v", res)
	}
	if res.EvidenceRef == "" {
		t.Fatal("报告必须固化证据并回填 ref（C-5）")
	}
	items, _ := led.List(ctx, admin(), "r", ledger.Filter{Tenant: "t-a"})
	if len(items) != 2 {
		t.Fatalf("台账应 2 条，实际 %d", len(items))
	}
	it := items[0]
	if it.Category != "代码密码类" || it.Source != "EXT-1/gitleaks" || it.Phase != "P4" {
		t.Errorf("台账字段口径错误: %+v", it)
	}
	if !strings.Contains(it.Note, "snapshot_ref=") {
		t.Errorf("note 应含证据回填: %s", it.Note)
	}
	// 证据可回溯同一报告原文
	b, err := s.ev.Get(ctx, res.EvidenceRef)
	if err != nil || !strings.Contains(string(b), "aws-access-key") {
		t.Errorf("证据回溯失败: %v", err)
	}

	// 重扫（同报告）：候选再次可摄取（unsupported=0），台账**不翻倍**（去重键）
	res2, err := s.ScanRepo(ctx, admin(), "r2", "t-a", t.TempDir(), "安全运营")
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewLedger != 0 || res2.Dup != 2 {
		t.Errorf("重扫应 new=0/dup=2，实际 %+v", res2)
	}
	if items, _ := led.List(ctx, admin(), "r", ledger.Filter{}); len(items) != 2 {
		t.Errorf("台账不得翻倍，实际 %d", len(items))
	}
	_ = cands
}

func TestScanRepoGates(t *testing.T) {
	ctx := context.Background()
	// 授权闸（含时间窗消费——authz.Validate 的 ErrNotInWindow 直接阻断扫描执行）
	s, _, _ := newSvc(t, errors.New("no scope"))
	if _, err := s.ScanRepo(ctx, admin(), "r", "t-a", ".", "安全运营"); err == nil {
		t.Error("无有效授权/窗外不得执行扫描（一票否决⑥+窗口承诺）")
	}
	// 越权租户：扫描入口即拒（不浪费子进程，不落任何队列）
	s2, led, cands := newSvc(t, nil)
	p := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}}
	if _, err := s2.ScanRepo(ctx, p, "r", "t-a", ".", "安全运营"); !errors.Is(err, rbac.ErrCrossTenant) {
		t.Errorf("越权应 ErrCrossTenant，实际 %v", err)
	}
	if len(cands.List()) != 0 || mustCount(led, p) != 0 {
		t.Error("越权扫描不得产生候选/台账")
	}
}

func mustCount(l *ledger.Service, p rbac.Principal) int {
	items, _ := l.List(context.Background(), p, "r", ledger.Filter{})
	return len(items)
}

func TestScanRepoBadReportGoesUnsupported(t *testing.T) {
	l := &audit.MemLog{}
	cands := candidate.NewService()
	ev, _ := evidence.NewFileStore(t.TempDir())
	s := New(cands, ledger.NewService(ledger.NewMemStore(), l), fakeGate{nil}, ev,
		func(ctx context.Context, bin string, args []string) error {
			return os.WriteFile(args[len(args)-1], []byte("}{broken"), 0o600)
		})
	_, err := s.ScanRepo(context.Background(), admin(), "r", "t-a", t.TempDir(), "安全运营")
	if err == nil {
		t.Error("坏报告必须报错上浮（不静默=与 unsupported 语义区分）")
	}
	_ = time.Now
}
