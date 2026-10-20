package httpapi

// M4-07 / FR-HRN-10 端点测试：summary 汇总读、budget 设置（权限/必填/跨租户）。
// 为什么：计量是治理面——无权限不可改预算口径（人在环可追溯），跨租户不可读。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
)

func newUsageServer(t *testing.T) (*httptest.Server, *usage.Service) {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u5", Role: "R5", TenantIDs: []string{"t-a"}},
		"tok-tb":    {UserID: "u2", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	us := usage.New(usage.NewMemStore())
	srv := httptest.NewServer(New(tenant.NewService(ts, l), nil, tokens,
		WithUsage(us)).Handler())
	t.Cleanup(srv.Close)
	return srv, us
}

func TestUsageSummaryEndpoint(t *testing.T) {
	srv, us := newUsageServer(t)
	ctx := context.Background()
	// 预置两笔计量（t-a），t-b 不计（租户隔离）
	if _, err := us.Record(ctx, usage.Event{Tenant: "t-a", Feature: "mm", Model: "m1",
		PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150, TS: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := us.Record(ctx, usage.Event{Tenant: "t-a", Feature: "shadow_ai", Model: "m2",
		PromptTokens: 10, CompletionTokens: 40, TotalTokens: 50, TS: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	resp, body := get2(srv.URL+"/v1/tenants/t-a/usage/summary", "tok-admin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"total_tokens":200`) {
		t.Fatalf("summary 汇总期望 200/200 tokens: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"mm"`) || !strings.Contains(body, `"shadow_ai"`) {
		t.Fatalf("byFeature 灰度观测面缺失: %s", body)
	}
	// 跨租户：t-b 主体读 t-a → 403（deny 面与其他租户级端点一致）
	resp, _ = get2(srv.URL+"/v1/tenants/t-a/usage/summary", "tok-tb")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("跨租户读 summary 应 403: %d", resp.StatusCode)
	}
}

func TestUsageBudgetEndpoint(t *testing.T) {
	srv, _ := newUsageServer(t)
	// 正常设置（R7 有 PermManageTenants）
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/usage/budget", "tok-admin", `{"monthly_tokens":1000,"by":"u7"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"budget_set":true`) {
		t.Fatalf("预算设置期望 200: %d %s", resp.StatusCode, body)
	}
	// 缺 monthly_tokens=400（必填，不猜默认值）
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/usage/budget", "tok-admin", `{"by":"u7"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 monthly_tokens 应 400: %d %s", resp.StatusCode, body)
	}
	// 缺 by=400（人在环：口径变更可追溯）
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/usage/budget", "tok-admin", `{"monthly_tokens":100}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 by 应 400: %d %s", resp.StatusCode, body)
	}
	// R5 无 PermManageTenants=403
	resp, _ = post(t, srv.URL, "/v1/tenants/t-a/usage/budget", "tok-ro", `{"monthly_tokens":100,"by":"u5"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("R5 设预算应 403: %d", resp.StatusCode)
	}
	// 跨租户：t-b 主体改 t-a 预算 → 403
	resp, _ = post(t, srv.URL, "/v1/tenants/t-a/usage/budget", "tok-tb", `{"monthly_tokens":100,"by":"u2"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("跨租户设预算应 403: %d", resp.StatusCode)
	}
}
