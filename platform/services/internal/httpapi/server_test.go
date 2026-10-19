package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func newTestServer(t *testing.T) (*httptest.Server, *audit.MemLog) {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()

	tstore := tenant.NewMemStore()
	for _, id := range []string{"t-a", "t-b"} {
		if err := tstore.Create(ctx, tenant.Tenant{ID: id, Name: id, Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	astore := asset.NewMemStore()
	seed := asset.Asset{
		ID: "a-in-ta", Tenant: "t-a", Name: "a.hddata.cn", Type: "domain", TypeLabel: "域名",
		Risk: "high", Exp: 60, Owner: "运维部", Found: time.Now(),
		Status: "在用", Beian: "已备案", Source: "P2/Fofa", Biz: "门户",
	}
	if err := astore.Create(ctx, seed); err != nil {
		t.Fatal(err)
	}
	other := seed
	other.ID = "a-in-tb"
	other.Tenant = "t-b"
	if err := astore.Create(ctx, other); err != nil {
		t.Fatal(err)
	}

	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u5", Role: "R5", TenantIDs: []string{"t-a"}},
	}
	srv := httptest.NewServer(New(
		tenant.NewService(tstore, l),
		asset.NewService(astore, l),
		tokens,
	).Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

func get(srv *httptest.Server, path, token string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// A-09 安全测试（一票否决④）：为什么——跨租户读取一旦放行即数据串权事故；
// 不仅要 403，还必须留下可取证的 deny 审计（CR-001）。
func TestCrossTenantReadDeniedAndAudited(t *testing.T) {
	srv, l := newTestServer(t)
	before := len(l.Snapshot())

	resp, body := get(srv, "/v1/assets/a-in-tb", "tok-ta") // t-a 主体读 t-b 资产
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("期望 403，实际 %d body=%v", resp.StatusCode, body)
	}
	errObj, _ := body["error"].(map[string]any)
	if errObj == nil || errObj["code"] != "cross_tenant_denied" {
		t.Errorf("错误契约不符: %v", body)
	}
	if errObj["request_id"] == "" {
		t.Error("错误响应必须携带 request_id（IR 统一约定）")
	}

	after := l.Snapshot()
	if len(after) <= before {
		t.Fatal("跨租户拒绝必须新增审计条目")
	}
	last := after[len(after)-1]
	if last.Result != audit.ResultDeny || last.Action != "asset.read" || last.TenantID != "t-b" {
		t.Errorf("审计条目字段不符: %+v", last)
	}
}

func TestUnauthorizedWithoutToken(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, _ := get(srv, "/v1/tenants", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无令牌期望 401，实际 %d", resp.StatusCode)
	}
}

func TestListAssetsOnlyReturnsOwnTenant(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, body := get(srv, "/v1/tenants/t-a/assets", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	items, _ := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("t-a 应只有 1 条资产，实际 %v", items)
	}
	first := items[0].(map[string]any)
	if first["id"] != "a-in-ta" || first["tenant"] != "t-a" {
		t.Errorf("资产字段不符: %v", first)
	}
}

func TestCreateAssetMissingRequiredReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	payload := map[string]any{"id": "a-new", "type": "domain"} // 缺 name/owner/status/...
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tenants/t-a/assets", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer tok-ta")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺必填字段期望 400，实际 %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	errObj := out["error"].(map[string]any)
	if errObj["code"] != "invalid_request" {
		t.Errorf("错误码期望 invalid_request，实际 %v", errObj["code"])
	}
}

func TestReadOnlyRoleCannotCreateAsset(t *testing.T) {
	srv, l := newTestServer(t)
	before := len(l.Snapshot())
	full := map[string]any{
		"id": "a-x", "name": "x.cn", "type": "domain", "type_label": "域名",
		"risk": "low", "exp": 10, "owner": "运维部",
		"found":  time.Now().Format(time.RFC3339),
		"status": "在用", "beian": "已备案", "source": "P1/百度", "biz": "测试",
	}
	b, _ := json.Marshal(full)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tenants/t-a/assets", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer tok-ro") // R5 只读
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("只读角色创建期望 403，实际 %d", resp.StatusCode)
	}
	after := l.Snapshot()
	if len(after) <= before {
		t.Error("权限拒绝必须落审计")
	}
}

func TestTenantCRUDFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	// R1 创建租户 → 403
	b, _ := json.Marshal(map[string]any{"id": "t-c", "name": "丙公司"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tenants", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer tok-ta")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("R1 创建租户期望 403，实际 %d", resp.StatusCode)
	}
	// R7 创建 → 201
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/tenants", bytes.NewReader(b))
	req2.Header.Set("Authorization", "Bearer tok-admin")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Errorf("R7 创建租户期望 201，实际 %d", resp2.StatusCode)
	}
	// 管理员列表含 3 家；R1 只见 t-a
	_, adminList := get(srv, "/v1/tenants", "tok-admin")
	if items, _ := adminList["items"].([]any); len(items) != 3 {
		t.Errorf("管理员应见 3 家租户，实际 %v", items)
	}
	_, ownList := get(srv, "/v1/tenants", "tok-ta")
	if items, _ := ownList["items"].([]any); len(items) != 1 {
		t.Errorf("R1 应仅见 1 家租户，实际 %v", items)
	}
}
