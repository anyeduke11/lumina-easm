package mcp

// M4-04 / WP-M4-04 测试：分级注册表（C-4 level 字段）、新只读工具 Scope 过滤、
// 受控/高危工具与 REST 同闸、allow/deny 全量审计、knowledge_export 如实边界。

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

func newFullServer(t *testing.T) (*httptest.Server, *audit.MemLog) {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	as := asset.NewMemStore()
	_ = as.Create(ctx, asset.Asset{ID: "a1", Tenant: "t-a", Name: "cache.hddata.cn", Type: "domain",
		Risk: "high", Exp: 70, Owner: "运维", Found: time.Now(), Status: "在用", Beian: "已备案", Source: "P2",
		Biz: "x", IP: "1.1.1.1", Tags: []string{"redis"}})
	led := ledger.NewService(ledger.NewMemStore(), l)
	az := authz.NewService(authz.NewMemStore(), l)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(candidate.NewService(), led, az, ev, nil) // 闸面在 collect 内部；本测试只验 MCP 层闸
	col.WithLimiter(az)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u5", Role: "R3", TenantIDs: []string{"t-a"}}, // 只读：无 write_assets
		"tok-tb":    {UserID: "u2", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	mon := monitor.New(vuln.NewService(), intel.NewService(), func() map[string][]asset.Asset { return nil })
	_, _ = mon.Add("m", "both", time.Hour)
	_, _ = mon.RunVisible(1, map[string][]asset.Asset{"t-a": {{
		ID: "a1", Tenant: "t-a", Name: "cache.hddata.cn", Tags: []string{"redis"}}}}) // 产出高危告警
	sv := sweep.NewService(as, classify.New(), led)
	mcpS := New(tenant.NewService(ts, l), asset.NewService(as, l), tokens,
		WithLedger(led), WithSweep(sv),
		WithMonitor(mon),
		WithWorkOrders(workorder.NewService(workorder.NewMemStore(), l, led)),
		WithNotices(notice.NewService(notice.NewMemStore(), l, led)),
		WithReport(report.NewService(report.NewMemStore(), l, tenant.NewService(ts, l), led)),
		WithPaths(graph.NewMemPath(graph.NewMemStore())),
		WithVulnIntel(vuln.NewService(), intel.NewService()),
		WithCollect(col),
		WithAudit(l))
	srv := httptest.NewServer(mcpS.Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

// C-4 口径落代码：tools/list 全量携带 level，枚举合法；高危/受控标注正确。
func TestMCPToolsHaveLevels(t *testing.T) {
	srv, _ := newFullServer(t)
	out := rpc(t, srv.URL, "tools/list", nil, "tok-admin")
	tools, _ := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 15 { // §8.1 出口矩阵：MCP ≥15 工具
		t.Fatalf("全量开放后应 ≥15 工具，实际 %d", len(tools))
	}
	levels := map[string]string{}
	for _, raw := range tools {
		tl := raw.(map[string]any)
		lv, _ := tl["level"].(string)
		if lv != LevelReadonly && lv != LevelControlled && lv != LevelDangerous {
			t.Fatalf("工具 %v level 非法: %q", tl["name"], lv)
		}
		levels[tl["name"].(string)] = lv
	}
	if levels["scan_active"] != LevelDangerous {
		t.Errorf("scan_active 应为 dangerous: %q", levels["scan_active"])
	}
	if levels["scan_schedule"] != LevelControlled || levels["report_generate"] != LevelControlled {
		t.Errorf("受控级标注错误: %q %q", levels["scan_schedule"], levels["report_generate"])
	}
}

// 只读 list_alerts：Scope 过滤在工具层强制——t-b 主体看不到 t-a 告警（AX-5 无特权）。
func TestMCPListAlertsScoped(t *testing.T) {
	srv, _ := newFullServer(t)
	out := rpc(t, srv.URL, "tools/call", map[string]any{"name": "list_alerts", "arguments": map[string]any{}}, "tok-admin")
	txt := toolText(t, out)
	if !strings.Contains(txt, "vuln_match|CVE-") {
		t.Fatalf("admin 应见 t-a 告警: %q", txt)
	}
	outB := rpc(t, srv.URL, "tools/call", map[string]any{"name": "list_alerts", "arguments": map[string]any{}}, "tok-tb")
	if tb := toolText(t, outB); strings.Contains(tb, "vuln_match|CVE-") {
		t.Fatalf("t-b 主体不得见 t-a 告警: %q", tb)
	}
}

// 租户面只读工具：缺 tenant_id=报错；越权 tenant_id=deny+审计。
func TestMCPTenantScopedTools(t *testing.T) {
	srv, l := newFullServer(t)
	// 缺 tenant_id
	out := rpc(t, srv.URL, "tools/call", map[string]any{"name": "list_workorders", "arguments": map[string]any{}}, "tok-admin")
	if res, _ := out["result"].(map[string]any); res["isError"] != true {
		t.Fatalf("缺 tenant_id 应报错: %v", out)
	}
	// 本租户 200 语义（空列表）
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "list_workorders",
		"arguments": map[string]any{"tenant_id": "t-a"}}, "tok-ta")
	if res, _ := out["result"].(map[string]any); res["isError"] == true {
		t.Fatalf("本租户查询不得报错: %v", out)
	}
	// 越权
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "list_notices",
		"arguments": map[string]any{"tenant_id": "t-b"}}, "tok-ta")
	if res, _ := out["result"].(map[string]any); res["isError"] != true ||
		!strings.Contains(toolText(t, out), "cross-tenant") {
		t.Fatalf("跨租户 list_notices 应 deny: %v", out)
	}
	// deny 审计留痕（授权审计完整）
	found := false
	for _, e := range l.Snapshot() {
		if e.Action == "mcp.list_notices" && e.Result == audit.ResultDeny && e.TenantID == "t-b" {
			found = true
		}
	}
	if !found {
		t.Fatalf("跨租户 deny 审计缺失: %+v", l.Snapshot())
	}
}

// 受控级 scan_schedule：与 REST 同闸——R3 无 write_assets 拒绝（deny 审计），
// R1 本租户可触发（返回 sweep id）。
func TestMCPScanScheduleGate(t *testing.T) {
	srv, l := newFullServer(t)
	out := rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_schedule",
		"arguments": map[string]any{"tenant_id": "t-a"}}, "tok-ro")
	if res, _ := out["result"].(map[string]any); res["isError"] != true ||
		!strings.Contains(toolText(t, out), "requires write_assets") {
		t.Fatalf("R3 触发排查应拒绝: %v", out)
	}
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_schedule",
		"arguments": map[string]any{"tenant_id": "t-a"}}, "tok-ta")
	if res, _ := out["result"].(map[string]any); res["isError"] == true {
		t.Fatalf("R1 本租户触发应成功: %v", out)
	}
	if !strings.Contains(toolText(t, out), `"id":"S-`) {
		t.Fatalf("应返回 sweep id: %q", toolText(t, out))
	}
	allowFound, denyFound := false, false
	for _, e := range l.Snapshot() {
		if e.Action == "mcp.scan_schedule" && e.Result == audit.ResultAllow {
			allowFound = true
		}
		if e.Action == "mcp.scan_schedule" && e.Result == audit.ResultDeny {
			denyFound = true
		}
	}
	if !allowFound || !denyFound {
		t.Fatalf("scan_schedule allow/deny 审计缺失: allow=%v deny=%v", allowFound, denyFound)
	}
}

// 高危级 scan_active（AX-5）：权限/Scope 拒绝面+deny 审计；未装配=工具不注册（不冒充）。
func TestMCPScanActiveGate(t *testing.T) {
	// ① 未装配：工具不进注册表 → unknown tool（501 语义的 MCP 形态）
	l0 := &audit.MemLog{}
	s0 := New(tenant.NewService(tenant.NewMemStore(), l0), asset.NewService(asset.NewMemStore(), l0),
		map[string]rbac.Principal{"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}})
	srv0 := httptest.NewServer(s0.Handler())
	defer srv0.Close()
	out := rpc(t, srv0.URL, "tools/call", map[string]any{"name": "scan_active",
		"arguments": map[string]any{"tenant_id": "t-a", "mode": "port", "target": "127.0.0.1"}}, "tok-admin")
	if out["error"] == nil {
		if res, _ := out["result"].(map[string]any); res["isError"] != true {
			t.Fatalf("未装配 scan_active 不得成功: %v", out)
		}
	}

	// ② 装配后：Scope 闸在 collect 授权闸之前由 MCP 层强制
	srv, l := newFullServer(t)
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_active",
		"arguments": map[string]any{"tenant_id": "t-b", "mode": "port", "target": "x.cn", "ports": "80"}}, "tok-ta")
	if res, _ := out["result"].(map[string]any); res["isError"] != true ||
		!strings.Contains(toolText(t, out), "cross-tenant") {
		t.Fatalf("跨租户 scan_active 应 deny: %v", out)
	}
	denyFound := false
	for _, e := range l.Snapshot() {
		if e.Action == "mcp.scan_active" && e.Result == audit.ResultDeny && e.TenantID == "t-b" {
			denyFound = true
		}
	}
	if !denyFound {
		t.Fatalf("scan_active 跨租户 deny 审计缺失: %+v", l.Snapshot())
	}
}

// AX-5 同闸：确认闸开启后 scan_active 必须携带一次性确认（无特权路径）。
func TestMCPScanActiveConfirmationGate(t *testing.T) {
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	as := asset.NewMemStore()
	az := authz.NewService(authz.NewMemStore(), l)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	col := collect.New(candidate.NewService(), ledger.NewService(ledger.NewMemStore(), l), az, ev, nil)
	cs := confirm.New(confirm.NewMemStore(), l)
	tokens := map[string]rbac.Principal{
		"tok-ta": {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(as, l), tokens,
		WithCollect(col), WithConfirmation(cs, true), WithAudit(l)).Handler())
	defer srv.Close()
	args := map[string]any{"tenant_id": "t-a", "mode": "port", "target": "127.0.0.1", "ports": "80"}

	// 缺确认 → 拒绝 + deny 审计（未进入采集授权层）
	out := rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_active", "arguments": args}, "tok-ta")
	if res, _ := out["result"].(map[string]any); res["isError"] != true ||
		!strings.Contains(toolText(t, out), "confirmation required") {
		t.Fatalf("缺确认应拒绝: %v", out)
	}
	denyFound := false
	for _, e := range l.Snapshot() {
		if e.Action == "mcp.scan_active" && e.Result == audit.ResultDeny && e.TenantID == "t-a" {
			denyFound = true
		}
	}
	if !denyFound {
		t.Fatalf("缺确认 deny 审计缺失: %+v", l.Snapshot())
	}

	// 有效确认 → 过确认闸（随后由采集授权闸拒绝=证明已进入下一层且未绕过授权）
	c, err := cs.Create(ctx, tokens["tok-ta"], "test", confirm.Confirmation{
		EntityID: "t-a", Action: "scan.port", Resource: "127.0.0.1",
		Method: confirm.MethodPassword, Reason: "test",
	})
	if err != nil {
		t.Fatalf("创建确认失败: %v", err)
	}
	args["confirmation_id"] = c.ID
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_active", "arguments": args}, "tok-ta")
	if txt := toolText(t, out); strings.Contains(txt, "confirmation required") {
		t.Fatalf("有效确认不得被确认闸拒绝: %q", txt)
	}
	// 一次性：复用同一确认 → consumed
	out = rpc(t, srv.URL, "tools/call", map[string]any{"name": "scan_active", "arguments": args}, "tok-ta")
	if txt := toolText(t, out); !strings.Contains(txt, "already consumed") {
		t.Fatalf("确认须一次性（复用应报 consumed）: %q", txt)
	}
}

// knowledge_export（F12/AIL-9）：ENH-02 未装=如实标注，不冒充已向量化。
func TestMCPKnowledgeExportHonesty(t *testing.T) {
	srv, _ := newFullServer(t)
	out := rpc(t, srv.URL, "tools/call", map[string]any{"name": "knowledge_export", "arguments": map[string]any{}}, "tok-admin")
	txt := toolText(t, out)
	for _, want := range []string{`"vector_store":"not_configured"`, `"ingested":false`, `"vulns":[`} {
		if !strings.Contains(txt, want) {
			t.Fatalf("knowledge_export 缺 %s: %q", want, txt)
		}
	}
	if strings.Contains(txt, `"embedding"`) {
		t.Error("导出面不得伪造 embedding 载荷")
	}
}
