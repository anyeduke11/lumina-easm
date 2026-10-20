package collect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（K3 条件②挂账闭合 + P3 主动探测渠道上线）：
// scope.rate_limit 必须成为**下发到工具参数的真实约束**（nmap --max-rate / ffuf -rate），
// 否则授权书写了限速、系统没做=合同风险（与 time_window 同罪）；主动探测同样必须
// 走授权闸（有效期+窗口）。高危端口才入风险台账（全量端口只进候选复核面=防刷屏，
// 入账动作=删除/限源可整改项）。

// fakeLimit 授权参数读口（authz.Service.Get 同签名，rate 可控）。
type fakeLimit struct{ rate int }

func (f fakeLimit) Get(context.Context, string) (authz.Scope, bool, error) {
	return authz.Scope{RateLimit: f.rate}, true, nil
}

// newActiveSvc 假执行器按工具写对应产物（-oG / -o 的**后继参数**定位输出路径），
// 并记录末次 args 供限速断言。
func newActiveSvc(t *testing.T, gateErr error, rate int) (*Service, *ledger.Service, *candidate.Service, *[]string) {
	t.Helper()
	l := &audit.MemLog{}
	led := ledger.NewService(ledger.NewMemStore(), l)
	cands := candidate.NewService()
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var lastArgs []string
	s := New(cands, led, fakeGate{gateErr}, ev,
		func(ctx context.Context, bin string, args []string) error {
			lastArgs = args
			idx := -1
			for i, a := range args {
				if a == "-oG" || a == "-o" {
					idx = i
				}
			}
			if idx < 0 || idx+1 >= len(args) {
				return errors.New("假执行器：未找到输出参数")
			}
			out := sampleNmapG()
			if bin == "ffuf" {
				out = sampleFfuf()
			}
			return os.WriteFile(args[idx+1], []byte(out), 0o600)
		})
	s.WithLimiter(fakeLimit{rate})
	return s, led, cands, &lastArgs
}

func TestScanPortFullChain(t *testing.T) {
	ctx := context.Background()
	s, led, cands, args := newActiveSvc(t, nil, 50)
	res, err := s.ScanPort(ctx, admin(), "r1", "t-a", "127.0.0.1", "22,3389,9000,18080", "安全运营")
	if err != nil {
		t.Fatal(err)
	}
	// 限速消费：--max-rate 必须出现在真实下发参数里（K3 条件②的执行证据）
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "--max-rate 50") {
		t.Errorf("rate_limit 未消费进 nmap 参数: %s", joined)
	}
	if res.Findings != 4 || res.EvidenceRef == "" {
		t.Fatalf("4 open 端口候选+证据锚必在，实际 %+v", res)
	}
	if res.NewLedger != 1 {
		t.Errorf("仅高危端口(3389)入台账，实际 %+v", res)
	}
	items, _ := led.List(ctx, admin(), "r", ledger.Filter{Tenant: "t-a"})
	if len(items) != 1 || !strings.Contains(items[0].Asset, "3389") ||
		items[0].Phase != "P3" || items[0].Source != "SCAN-1/nmap" {
		t.Errorf("高危端口台账口径错误: %+v", items)
	}
	if len(cands.List()) != 4 {
		t.Errorf("全量端口候选应进复核面=4，实际 %d", len(cands.List()))
	}

	// 重扫：台账不翻倍（tenant|ip|port 去重键）
	res2, err := s.ScanPort(ctx, admin(), "r2", "t-a", "127.0.0.1", "22,3389,9000,18080", "安全运营")
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewLedger != 0 || res2.Dup != 1 {
		t.Errorf("重扫应 new=0/dup=1，实际 %+v", res2)
	}

	// 无授权=拒跑（主动探测受一票否决⑥+窗口约束）
	s3, _, _, _ := newActiveSvc(t, errors.New("no scope"), 0)
	if _, err := s3.ScanPort(ctx, admin(), "r", "t-a", "127.0.0.1", "22", ""); err == nil {
		t.Error("无有效授权/窗外不得端口探测")
	}
	// 无 rate_limit（0）= 不注入限速参数（空=不限，语义与 authz 窗口一致）
	s4, _, _, args4 := newActiveSvc(t, nil, 0)
	if _, err := s4.ScanPort(ctx, admin(), "r", "t-a", "127.0.0.1", "22", ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*args4, " "), "--max-rate") {
		t.Error("rate_limit=0 不应下发限速参数")
	}
}

// targetGate 整体闸通过但细目标拒（模拟授权端口/IP 面收窄）——证明 CheckTarget
// 消费独立存在（旁路该闸=范围外端口混入候选，必须被本用例捕获）。
// port=0 的执行前主机预检放行：本用例模拟的是「主机在授权面、端口收窄」，
// 主机级越界由 TestScanPortRejectsOutOfScopeLiteralIPBeforeExec 单独守卫。
type targetGate struct{ tErr error }

func (g targetGate) Validate(context.Context, string) error { return nil }
func (g targetGate) CheckTarget(_ context.Context, _ rbac.Principal, _, _, _ string, port int) error {
	if port == 0 {
		return nil
	}
	return g.tErr
}
func (g targetGate) RequireSecondAuth(context.Context, string) error { return nil }

// noSecondGate 二次授权缺失（爆破类动作必须被护栏 5 闸拒绝——ScanDir 与 ScanPort
// 的区别测试：端口探测不属爆破类，不受此闸约束）。
type noSecondGate struct{}

func (noSecondGate) Validate(context.Context, string) error { return nil }
func (noSecondGate) CheckTarget(context.Context, rbac.Principal, string, string, string, int) error {
	return nil
}
func (noSecondGate) RequireSecondAuth(context.Context, string) error { return authz.ErrNoSecondAuth }

func TestScanDirRequiresSecondAuth(t *testing.T) {
	l := &audit.MemLog{}
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(candidate.NewService(), ledger.NewService(ledger.NewMemStore(), l), noSecondGate{}, ev,
		func(ctx context.Context, bin string, args []string) error {
			return errors.New("爆破类闸拒后不得调用工具")
		})
	_, err = s.ScanDir(context.Background(), admin(), "r", "t-a", "http://127.0.0.1:9000", "")
	if !errors.Is(err, authz.ErrNoSecondAuth) {
		t.Errorf("目录爆破必须消费二次授权闸，实际 %v", err)
	}
}

func TestScanPortTargetGate(t *testing.T) {
	l := &audit.MemLog{}
	cands := candidate.NewService()
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(cands, ledger.NewService(ledger.NewMemStore(), l), targetGate{authz.ErrNotInScope}, ev,
		func(ctx context.Context, bin string, args []string) error {
			for i, a := range args {
				if a == "-oG" {
					return os.WriteFile(args[i+1], []byte(sampleNmapG()), 0o600)
				}
			}
			return errors.New("缺 -oG")
		})
	res, err := s.ScanPort(context.Background(), admin(), "r", "t-a", "127.0.0.1", "22,3389", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 0 || res.NewLedger != 0 || len(cands.List()) != 0 {
		t.Errorf("授权面外端口不得进候选/台账，实际 %+v cands=%d", res, len(cands.List()))
	}
}

func TestScanDirFullChain(t *testing.T) {
	ctx := context.Background()
	s, led, _, args := newActiveSvc(t, nil, 30)
	res, err := s.ScanDir(ctx, admin(), "r1", "t-a", "http://127.0.0.1:9000", "安全运营")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "-rate 30") {
		t.Errorf("rate_limit 未消费进 ffuf 参数: %s", joined)
	}
	if res.Findings != 2 || res.NewLedger != 2 || res.EvidenceRef == "" {
		t.Fatalf("2 命中全入账，实际 %+v", res)
	}
	items, _ := led.List(ctx, admin(), "r", ledger.Filter{Tenant: "t-a"})
	if items[0].Category != "系统架构类" || items[0].Source != "SCAN-2/ffuf" || items[0].Phase != "P3" {
		t.Errorf("目录暴露台账口径错误: %+v", items[0])
	}
	// 重扫不翻倍
	res2, _ := s.ScanDir(ctx, admin(), "r2", "t-a", "http://127.0.0.1:9000", "安全运营")
	if res2.NewLedger != 0 || res2.Dup != 2 {
		t.Errorf("重扫应 new=0/dup=2，实际 %+v", res2)
	}
	// 台账条目均可回溯证据（候选 JSONL 与 finding 载荷一致）
	it := items[0]
	if !strings.Contains(it.Note, "snapshot_ref=") {
		t.Errorf("note 缺证据回填: %s", it.Note)
	}
	_ = json.Marshal
}
