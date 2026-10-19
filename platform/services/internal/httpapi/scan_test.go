package httpapi

import (
	"context"
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

// 为什么（M2-01 端点接线）：scan:repo 是采集四闸管道（写权限/租户/授权+窗/契约）
// 的对外入口——端点层验装配正确与授权 403 透传（管道内部门证 collect 包已测）。
func newScanServer(t *testing.T) (*httptest.Server, *authz.Service) {
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
			return os.WriteFile(args[len(args)-1],
				[]byte(`[{"RuleID":"aws-access-key","Description":"AWS Access Key","StartLine":1,"File":"app.env","Tags":["key"],"Fingerprint":"f1"}]`), 0o600)
		})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(tenant.NewMemStore(), l),
		asset.NewService(asset.NewMemStore(), l), tokens,
		WithAuthz(az), WithLedger(led), WithCollect(col)).Handler())
	t.Cleanup(srv.Close)
	return srv, az
}

func TestScanRepoEndpoint(t *testing.T) {
	srv, az := newScanServer(t)
	dir := t.TempDir()
	// 无有效授权 → 403 no_valid_scope（扫描不执行=一票否决⑥同型）
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/scan:repo", "tok-admin", `{"dir":"`+dir+`"}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "no_valid_scope") {
		t.Fatalf("无授权应 403 no_valid_scope: %d %s", resp.StatusCode, body)
	}
	// 授权后（窗口空=不限）→ 200 管道计数
	if err := az.Upsert(context.Background(), rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"r", authz.Scope{Tenant: "t-a", Domains: []string{"a.cn"},
			ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(time.Hour),
			Signer: "s", DocHash: "h"}); err != nil {
		t.Fatal(err)
	}
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/scan:repo", "tok-admin", `{"dir":"`+dir+`"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"new_ledger":1`) {
		t.Fatalf("授权后扫描应入账: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"evidence_ref":"file://`) {
		t.Errorf("证据回填缺失: %s", body)
	}
	// 重扫 → dup=1 不翻倍
	_, body2 := post(t, srv.URL, "/v1/tenants/t-a/scan:repo", "tok-admin", `{"dir":"`+dir+`"}`)
	if !strings.Contains(body2, `"new_ledger":0`) || !strings.Contains(body2, `"dup":1`) {
		t.Errorf("重扫去重失败: %s", body2)
	}
	// 只读角色 → 403
	if resp, _ = post(t, srv.URL, "/v1/tenants/t-a/scan:repo", "tok-ro", `{"dir":"`+dir+`"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("只读角色扫描应 403，实际 %d", resp.StatusCode)
	}
	// 缺 dir → 400
	if resp, _ = post(t, srv.URL, "/v1/tenants/t-a/scan:repo", "tok-admin", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("dir 必填应 400，实际 %d", resp.StatusCode)
	}
}
