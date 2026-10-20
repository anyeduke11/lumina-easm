package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（P0-4 采集加固）：子进程参数来自请求体，若不校验=选项注入面
// （target="--version" 会被 nmap 当选项）；目标越界若不执行前拦截=对范围外
// 主机真实发包（一票否决⑥）。工具缺失必须映射为「能力缺失」（501
// tool_unavailable），不得伪装成「扫描无发现」。

func newHardeningSvc(t *testing.T, gate Gate, execFn Exec) *Service {
	t.Helper()
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(candidate.NewService(), ledger.NewService(ledger.NewMemStore(), &audit.MemLog{}), gate, ev, execFn)
}

func TestValidHost(t *testing.T) {
	good := []string{"example.com", "127.0.0.1", "2001:db8::1", "a-b_c.example"}
	for _, h := range good {
		if err := validHost(h); err != nil {
			t.Errorf("合法主机 %q 被拒: %v", h, err)
		}
	}
	bad := []string{"", "--version", "-iL", "example.com;rm", "a b", "example.com/24"}
	for _, h := range bad {
		if err := validHost(h); !errors.Is(err, ErrBadTarget) {
			t.Errorf("非法主机 %q 应 ErrBadTarget，实际 %v", h, err)
		}
	}
}

func TestValidPorts(t *testing.T) {
	good := []string{"80", "80,443", "1000-2000", "22,3389,9000,18080", "1-65535"}
	for _, s := range good {
		if err := validPorts(s); err != nil {
			t.Errorf("合法端口表达式 %q 被拒: %v", s, err)
		}
	}
	bad := []string{"", "-p", "80;rm", "0", "65536", "9000-8000", "80-", "abc", "80,,443"}
	for _, s := range bad {
		if err := validPorts(s); !errors.Is(err, ErrBadTarget) {
			t.Errorf("非法端口表达式 %q 应 ErrBadTarget，实际 %v", s, err)
		}
	}
}

func TestDefaultExecToolMissing(t *testing.T) {
	err := DefaultExec(context.Background(), "easm-definitely-not-installed-xyz", nil)
	if !errors.Is(err, ErrToolMissing) {
		t.Fatalf("工具未安装应 ErrToolMissing（HTTP 501 tool_unavailable），实际 %v", err)
	}
}

func TestScanPortRejectsInvalidInputBeforeExec(t *testing.T) {
	cases := []struct {
		name, target, ports string
	}{
		{"选项注入主机", "--version", "80"},
		{"非法字符主机", "example.com;rm -rf /", "80"},
		{"非法端口字符", "example.com", "80;rm"},
		{"端口零", "example.com", "0"},
		{"端口越界", "example.com", "65536"},
		{"区间倒序", "example.com", "9000-8000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			s := newHardeningSvc(t, fakeGate{nil}, func(context.Context, string, []string) error {
				called = true
				return nil
			})
			_, err := s.ScanPort(context.Background(), admin(), "r", "t-a", tc.target, tc.ports, "")
			if !errors.Is(err, ErrBadTarget) {
				t.Fatalf("应 ErrBadTarget（HTTP 400），实际 %v", err)
			}
			if called {
				t.Error("语法非法输入不得启动子进程")
			}
		})
	}
}

// hostGate 主机级预检（port=0）拒绝、端口级放行——模拟字面量 IP 不在授权面。
type hostGate struct{ err error }

func (g hostGate) Validate(context.Context, string) error { return nil }
func (g hostGate) CheckTarget(_ context.Context, _ rbac.Principal, _, _, _ string, port int) error {
	if port == 0 {
		return g.err
	}
	return nil
}
func (g hostGate) RequireSecondAuth(context.Context, string) error { return nil }

func TestScanPortRejectsOutOfScopeLiteralIPBeforeExec(t *testing.T) {
	called := false
	s := newHardeningSvc(t, hostGate{authz.ErrNotInScope}, func(context.Context, string, []string) error {
		called = true
		return nil
	})
	_, err := s.ScanPort(context.Background(), admin(), "r", "t-a", "203.0.113.9", "80,443", "")
	if !errors.Is(err, authz.ErrNotInScope) {
		t.Fatalf("授权面外字面量 IP 应拒绝，实际 %v", err)
	}
	if called {
		t.Error("授权面外 IP 不得启动 nmap（一票否决⑥：不得对范围外主机发包）")
	}
}

func TestScanDirRejectsInvalidTarget(t *testing.T) {
	for _, target := range []string{"ftp://example.com", "//example.com", "example.com", "http://[bad", "http://example.com:0"} {
		called := false
		s := newHardeningSvc(t, fakeGate{nil}, func(context.Context, string, []string) error {
			called = true
			return nil
		})
		_, err := s.ScanDir(context.Background(), admin(), "r", "t-a", target, "")
		if !errors.Is(err, ErrBadTarget) {
			t.Errorf("非法爆破目标 %q 应 ErrBadTarget，实际 %v", target, err)
		}
		if called {
			t.Errorf("非法目标 %q 不得启动 ffuf", target)
		}
	}
}

func TestScanRepoRejectsOptionInjectionDir(t *testing.T) {
	called := false
	s := newHardeningSvc(t, fakeGate{nil}, func(context.Context, string, []string) error {
		called = true
		return nil
	})
	if _, err := s.ScanRepo(context.Background(), admin(), "r", "t-a", "  --source=/etc", ""); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("目录选项注入应 ErrBadTarget，实际 %v", err)
	}
	if called {
		t.Error("选项注入目录不得启动 gitleaks")
	}
}
