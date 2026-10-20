package httpapi

// M4-03 / FR-MON-003 端点测试：POC 触发→任务单→查询→人工闭环→终态 409。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

func newMonTaskServer(t *testing.T, asvc *asset.Service) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := t.Context()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ro":    {UserID: "u5", Role: "R5", TenantIDs: []string{"t-a"}},
		"tok-tb":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	mon := monitor.New(vuln.NewService(), intel.NewService(),
		func() map[string][]asset.Asset { return nil })
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asvc, tokens,
		WithMonitor(mon)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestMonitorTasksPocFlow(t *testing.T) {
	srv := newMonTaskServer(t, nil)
	// POC 触发（空 asset_ids=租户级）
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks:poc", "tok-admin", `{"cve":"CVE-2026-7777"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POC 触发期望 200: %d %s", resp.StatusCode, body)
	}
	// 查询任务单
	resp, body = get2(srv.URL+"/v1/tenants/t-a/monitors/tasks", "tok-admin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "CVE-2026-7777") {
		t.Fatalf("任务单查询失败: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Tasks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"tasks"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if len(out.Tasks) != 1 || !strings.HasPrefix(out.Tasks[0].ID, "RT-") {
		t.Fatalf("任务单元数据: %s", body)
	}
	tid := out.Tasks[0].ID
	// 人工闭环
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks/"+tid+"/done", "tok-admin", `{"by":"u1","note":"已重扫"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"done"`) {
		t.Fatalf("闭环期望 200: %d %s", resp.StatusCode, body)
	}
	// 终态重复闭环=409 task_closed（不得虚报）
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks/"+tid+"/done", "tok-admin", `{"by":"u1"}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "task_closed") {
		t.Fatalf("重复闭环应 409 task_closed: %d %s", resp.StatusCode, body)
	}
	// 缺完成人=400（人在环）
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks/"+tid+"/done", "tok-admin", `{"note":"无 by"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺完成人应 400: %d %s", resp.StatusCode, body)
	}
}

func TestMonitorTasksPocValidation(t *testing.T) {
	srv := newMonTaskServer(t, nil)
	// 缺 cve=400
	resp, _ := post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks:poc", "tok-admin", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 cve 期望 400，实际 %d", resp.StatusCode)
	}
	// R5 只读：写面 403
	resp2, _ := post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks:poc", "tok-ro", `{"cve":"CVE-1"}`)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("R5 触发 POC 期望 403，实际 %d", resp2.StatusCode)
	}
	// 跨租户：R1(t-b) 读 t-a=403
	resp3, _ := get2(srv.URL+"/v1/tenants/t-a/monitors/tasks", "tok-tb")
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("跨租户读任务单期望 403，实际 %d", resp3.StatusCode)
	}
}

func TestMonitorTasksPocAssetScope(t *testing.T) {
	// asset_ids 不在租户内=拒绝触发（不猜影响面）
	l := &audit.MemLog{}
	asvc := asset.NewService(asset.NewMemStore(), l)
	srv := newMonTaskServer(t, asvc)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/monitors/tasks:poc", "tok-admin",
		`{"cve":"CVE-1","asset_ids":["ghost-id"]}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "ghost-id") {
		t.Fatalf("越权资产 ID 应拒绝: %d %s", resp.StatusCode, body)
	}
}
