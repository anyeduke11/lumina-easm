package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

// 为什么（FR-CHN-004 对外可观测面）：五态跟踪必须经 REST 端到端可走——建单质量闸
// （必填/kind 枚举/幽灵台账 404/重复 409）、跳步伪造闭环 422、缺操作人 400、
// 主链推进 200+留痕、状态筛选、越权租户读/转 403。端点=平台对接与催办台的事实入口。
func newWorkServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	led := ledger.NewService(ledger.NewMemStore(), l)
	wos := workorder.NewService(workorder.NewMemStore(), l, led)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ops":   {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
	}
	srv := httptest.NewServer(New(tsvc, asset.NewService(asset.NewMemStore(), l), tokens,
		WithLedger(led), WithWorkOrders(wos)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

const goodLedgerWO = `{"id":"L-w1","phase":"P3","cat":"代码密码类","asset":"a.cn","title":"备份可下载","lv":"严重","src":"P3/scan","date":"2026-10-17T00:00:00Z","action":"删除","owner":"运维部","due":"2026-10-18T00:00:00Z"}`

const goodOrder = `{"ledger_id":"L-w1","channel":"repo.github","target":"https://github.com/x/y/blob/main/backup.sql","kind":"删除申请","platform":"GitHub","title":"泄露备份库文件","owner":"安全运营"}`

func TestWorkOrderEndpoints(t *testing.T) {
	srv := newWorkServer(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-w","name":"工单公司","short":"工单","root_domains":["w.cn"]}`)
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/ledger", "tok-admin", goodLedgerWO); r.StatusCode != http.StatusCreated {
		t.Fatal("台账条目建立失败")
	}

	// 质量闸：缺 kind=400、非法 kind=400、幽灵台账=404
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders", "tok-admin", `{"ledger_id":"L-w1","channel":"c","target":"u","kind":"","platform":"p","title":"t","owner":"o"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 kind 期望 400，实际 %d", r.StatusCode)
	}
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders", "tok-admin", strings.Replace(goodOrder, "删除申请", "警告", 1)); r.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 kind 期望 400，实际 %d", r.StatusCode)
	}
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders", "tok-admin", strings.Replace(goodOrder, "L-w1", "L-GHOST", 1)); r.StatusCode != http.StatusNotFound {
		t.Errorf("幽灵台账期望 404，实际 %d", r.StatusCode)
	}

	// 建单 201=待整改+留痕；重复=409
	r1, body := post(t, srv.URL, "/v1/tenants/t-w/workorders", "tok-admin", goodOrder)
	if r1.StatusCode != http.StatusCreated || !strings.Contains(body, `"status":"待整改"`) || !strings.Contains(body, "WO-") {
		t.Fatalf("建单期望 201+待整改: %d %s", r1.StatusCode, body)
	}
	id := extractJSONField(body, "id")
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders", "tok-admin", goodOrder); r.StatusCode != http.StatusConflict {
		t.Errorf("重复建单期望 409，实际 %d", r.StatusCode)
	}

	// 转移闸：跳步 422、缺操作人 400、主链 200
	if r, b := post(t, srv.URL, "/v1/tenants/t-w/workorders/"+id+"/advance", "tok-admin", `{"to":"已下架","operator":"op"}`); r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(b, "illegal_state_transition") {
		t.Errorf("跳步期望 422，实际 %d %s", r.StatusCode, b)
	}
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders/"+id+"/advance", "tok-admin", `{"to":"处置中"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("缺操作年期望 400，实际 %d", r.StatusCode)
	}
	r2, b2 := post(t, srv.URL, "/v1/tenants/t-w/workorders/"+id+"/advance", "tok-admin", `{"to":"处置中","operator":"红队甲","note":"受理"}`)
	if r2.StatusCode != http.StatusOK || !strings.Contains(b2, `"status":"处置中"`) || !strings.Contains(b2, "红队甲") {
		t.Errorf("主链推进期望 200+处置中+留痕: %d %s", r2.StatusCode, b2)
	}

	// 列举与筛选（非法 status=400）
	_, lb := get2(srv.URL+"/v1/tenants/t-w/workorders", "tok-admin")
	if !strings.Contains(lb, id) {
		t.Errorf("列表应含工单: %s", lb)
	}
	_, pb := get2(srv.URL+"/v1/tenants/t-w/workorders?status=待整改", "tok-admin")
	if strings.Contains(pb, id) {
		t.Errorf("转移后不应仍在待整改筛内: %s", pb)
	}
	if r, _ := get2(srv.URL+"/v1/tenants/t-w/workorders?status=乱写", "tok-admin"); r.StatusCode != http.StatusBadRequest {
		t.Errorf("非法筛选期望 400，实际 %d", r.StatusCode)
	}

	// 越权主体（tok-ops 只见 t-a）读/转 t-w → 403
	if r, _ := get2(srv.URL+"/v1/tenants/t-w/workorders/"+id, "tok-ops"); r.StatusCode != http.StatusForbidden {
		t.Errorf("越权读期望 403，实际 %d", r.StatusCode)
	}
	if r, _ := post(t, srv.URL, "/v1/tenants/t-w/workorders/"+id+"/advance", "tok-ops", `{"to":"处置中","operator":"x"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("越权转移期望 403，实际 %d", r.StatusCode)
	}
}

// extractJSONField 从 JSON 体里取一个顶层字符串字段（测试内轻量解析）。
func extractJSONField(body, field string) string {
	key := `"` + field + `":"`
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
