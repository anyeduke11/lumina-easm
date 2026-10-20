package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（P3 主动探测渠道对外入口）：scan:port/scan:dir 与 scan:repo 同受四闸约束，
// 且**时间窗对主动探测必须有真实拒绝面**（授权模板承诺「窗口外不做主动测试」）——
// 端点层用确定性窗外窗口验证 403 not_in_time_window 透传。

const nmapG = "Host: 127.0.0.1 (localhost)\tStatus: Up\n" +
	"Host: 127.0.0.1 (localhost)\tPorts: 22/open/tcp//ssh///, 3389/open/tcp//ms-wbt-server///,\n"

const ffufJSON = `{"results":[{"input":{"FUZZ":"admin"},"status":403,"length":289,"url":"http://127.0.0.1:9000/admin","content-type":"application/xml"}]}`

func newActiveScanServer(t *testing.T) (*httptest.Server, *authz.Service) {
	t.Helper()
	l := &audit.MemLog{}
	led := ledger.NewService(ledger.NewMemStore(), l)
	az := authz.NewService(authz.NewMemStore(), l)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(candidate.NewService(), led, az, ev,
		func(ctx context.Context, bin string, args []string) error {
			idx := -1
			for i, a := range args {
				if a == "-oG" || a == "-o" {
					idx = i
				}
			}
			out := nmapG
			if bin == "ffuf" {
				out = ffufJSON
			}
			return os.WriteFile(args[idx+1], []byte(out), 0o600)
		})
	col.WithLimiter(az) // 与生产装配同型（authz.Service 即参数读口）
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(tenant.NewMemStore(), l),
		asset.NewService(asset.NewMemStore(), l), tokens,
		WithAuthz(az), WithLedger(led), WithCollect(col)).Handler())
	t.Cleanup(srv.Close)
	return srv, az
}

func upsertScope(t *testing.T, az *authz.Service, tenantID, window string, rate int) {
	t.Helper()
	if err := az.Upsert(context.Background(), rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"r", authz.Scope{Tenant: tenantID, Domains: []string{"a.cn"}, CIDRs: []string{"127.0.0.0/8"},
			TimeWindow: window, RateLimit: rate, SecondAuth: true,
			ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(time.Hour),
			Signer: "s", DocHash: "h"}); err != nil {
		t.Fatal(err)
	}
}

// outsideWindow 确定性窗外窗口：当前 UTC+2 小时的第 0~1 分钟（此刻必在窗外）。
func outsideWindow() string {
	h := (time.Now().UTC().Hour() + 2) % 24
	return fmt.Sprintf("%02d:00-%02d:01", h, h)
}

func TestScanPortEndpoint(t *testing.T) {
	srv, az := newActiveScanServer(t)
	// 无授权 403
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"127.0.0.1"}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "no_valid_scope") {
		t.Fatalf("无授权应 403: %d %s", resp.StatusCode, body)
	}
	// 窗外授权 → 403 not_in_time_window（主动探测的窗口承诺对外可观测）
	upsertScope(t, az, "t-a", outsideWindow(), 50)
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"127.0.0.1"}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "not_in_time_window") {
		t.Fatalf("窗外应 403 not_in_time_window: %d %s", resp.StatusCode, body)
	}
	// 全天窗口+限速 → 200（仅高危 3389 入账，全量端口进候选）
	upsertScope(t, az, "t-a", "00:00-00:00", 50)
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"127.0.0.1"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"findings":2`) ||
		!strings.Contains(body, `"new_ledger":1`) || !strings.Contains(body, `"evidence_ref":"file://`) {
		t.Fatalf("探测管道异常: %d %s", resp.StatusCode, body)
	}
	// 重扫 dup 不翻倍
	_, body2 := post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"127.0.0.1"}`)
	if !strings.Contains(body2, `"new_ledger":0`) || !strings.Contains(body2, `"dup":1`) {
		t.Errorf("重扫去重失败: %s", body2)
	}
	// 缺 target → 400
	if resp, _ = post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("target 必填应 400，实际 %d", resp.StatusCode)
	}
	// 选项注入 target → 400（不落子进程；collect.ErrBadTarget 映射口径）
	if resp, body = post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"--version"}`); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "invalid_request") {
		t.Errorf("选项注入 target 应 400 invalid_request: %d %s", resp.StatusCode, body)
	}
}

// 工具未安装=能力缺失，映射 501 tool_unavailable（不是 500/空结果，不伪装成扫描失败）。
func TestScanPortToolMissingIs501(t *testing.T) {
	l := &audit.MemLog{}
	led := ledger.NewService(ledger.NewMemStore(), l)
	az := authz.NewService(authz.NewMemStore(), l)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(candidate.NewService(), led, az, ev,
		func(context.Context, string, []string) error {
			return fmt.Errorf("%w: nmap", collect.ErrToolMissing)
		})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(tenant.NewMemStore(), l),
		asset.NewService(asset.NewMemStore(), l), tokens,
		WithAuthz(az), WithLedger(led), WithCollect(col)).Handler())
	t.Cleanup(srv.Close)
	upsertScope(t, az, "t-a", "00:00-00:00", 0)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/scan:port", "tok-admin", `{"target":"127.0.0.1"}`)
	if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "tool_unavailable") {
		t.Fatalf("工具缺失应 501 tool_unavailable，实际 %d %s", resp.StatusCode, body)
	}
}

func TestScanDirEndpoint(t *testing.T) {
	srv, az := newActiveScanServer(t)
	upsertScope(t, az, "t-a", "00:00-00:00", 30)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/scan:dir", "tok-admin", `{"url":"http://127.0.0.1:9000"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"new_ledger":1`) {
		t.Fatalf("爆破应入账: %d %s", resp.StatusCode, body)
	}
	_, body2 := post(t, srv.URL, "/v1/tenants/t-a/scan:dir", "tok-admin", `{"url":"http://127.0.0.1:9000"}`)
	if !strings.Contains(body2, `"dup":1`) {
		t.Errorf("重扫 dup 失败: %s", body2)
	}
	// 非 http 目标 → 400
	if resp, _ = post(t, srv.URL, "/v1/tenants/t-a/scan:dir", "tok-admin", `{"url":"ftp://x"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("url 口径校验应 400，实际 %d", resp.StatusCode)
	}
}
