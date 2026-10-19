package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	as := asset.NewMemStore()
	_ = as.Create(ctx, asset.Asset{ID: "a1", Tenant: "t-a", Name: "www.hddata.cn", Type: "domain",
		Risk: "high", Exp: 70, Owner: "运维", Found: time.Now(), Status: "在用", Beian: "已备案", Source: "P2", Biz: "x", IP: "1.1.1.1"})
	_ = as.Create(ctx, asset.Asset{ID: "b1", Tenant: "t-b", Name: "secret.tob.cn", Type: "domain",
		Risk: "low", Exp: 5, Owner: "运维", Found: time.Now(), Status: "在用", Beian: "已备案", Source: "P2", Biz: "y"})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
	}
	return httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(as, l), tokens).Handler())
}

func rpc(t *testing.T, url, method string, params map[string]any, token string) map[string]any {
	t.Helper()
	pj, _ := json.Marshal(params)
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = json.RawMessage(pj)
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func toolText(t *testing.T, out map[string]any) string {
	t.Helper()
	res, _ := out["result"].(map[string]any)
	arr, _ := res["content"].([]any)
	if len(arr) == 0 {
		t.Fatalf("无 content: %v", out)
	}
	c := arr[0].(map[string]any)
	return c["text"].(string)
}

func TestInitializeAndToolsList(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	init := rpc(t, srv.URL, "initialize", map[string]any{}, "tok-admin")
	if init["result"].(map[string]any)["protocolVersion"] != protocolVersion {
		t.Errorf("initialize 协议版本错误: %v", init)
	}
	lst := rpc(t, srv.URL, "tools/list", nil, "tok-admin")
	names := lst["result"].(map[string]any)["tools"].([]any)
	if len(names) != 4 { // list_tenants/search_assets/get_asset/detect_sensitive_data（list_ledger 需注入 ledger）
		t.Fatalf("应 4 个工具，实际 %d", len(names))
	}
}

func TestUnauthenticated(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	out := rpc(t, srv.URL, "tools/list", nil, "")
	if out["error"] == nil {
		t.Error("无令牌应返回 JSON-RPC error")
	}
}

// 为什么（AX-5）：MCP 消费方即便拿到别的 asset_id，跨租户也读不到——get_asset 必须 403 语义。
func TestGetAssetCrossTenantDenied(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	out := rpc(t, srv.URL, "tools/call", map[string]any{
		"name":      "get_asset",
		"arguments": map[string]any{"asset_id": "b1"},
	}, "tok-ta") // t-a 主体读 t-b 资产
	res, _ := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("跨租户读取必须 isError=true，实际 %v", out)
	}
	if !strings.Contains(toolText(t, out), "cross-tenant") {
		t.Errorf("应报 cross-tenant，实际 %q", toolText(t, out))
	}
}

func TestGetAssetAllowed(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	out := rpc(t, srv.URL, "tools/call", map[string]any{
		"name":      "get_asset",
		"arguments": map[string]any{"asset_id": "a1"},
	}, "tok-ta")
	res, _ := out["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("本租户读取应成功，实际 isError: %v", out)
	}
	txt := toolText(t, out)
	if !strings.Contains(txt, "www.hddata.cn") {
		t.Errorf("应含资产名: %q", txt)
	}
	// C-6 字段口径：MCP 输出必须 snake_case（与 REST/DR-01 一致），禁止 Go 字段名外泄
	var obj map[string]any
	if err := json.Unmarshal([]byte(txt), &obj); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "tenant", "name", "type", "risk", "exp", "owner"} {
		if _, ok := obj[k]; !ok {
			t.Errorf("MCP 输出缺 snake_case 字段 %q: %q", k, txt)
		}
	}
	if _, bad := obj["Tenant"]; bad {
		t.Error("MCP 输出不得含 Go 字段名 Tenant（snake_case 口径）")
	}
}

// search_assets 不得越权：tok-ta 检索时看不到 t-b 资产（即使 q 命中）。
func TestSearchAssetsScoped(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	out := rpc(t, srv.URL, "tools/call", map[string]any{
		"name":      "search_assets",
		"arguments": map[string]any{"q": ".cn"},
	}, "tok-ta")
	txt := toolText(t, out)
	if strings.Contains(txt, "secret.tob.cn") {
		t.Errorf("检索泄露了 t-b 资产: %q", txt)
	}
	if !strings.Contains(txt, "www.hddata.cn") {
		t.Errorf("应含本租户资产: %q", txt)
	}
	// 显式跨租户 tenant_id 直接报错
	out2 := rpc(t, srv.URL, "tools/call", map[string]any{
		"name":      "search_assets",
		"arguments": map[string]any{"tenant_id": "t-b"},
	}, "tok-ta")
	res2, _ := out2["result"].(map[string]any)
	if res2["isError"] != true {
		t.Errorf("指定越权 tenant_id 应 isError，实际 %v", out2)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	out := rpc(t, srv.URL, "bogus/method", nil, "tok-admin")
	if out["error"] == nil {
		t.Error("未知方法应返回 error")
	}
}
