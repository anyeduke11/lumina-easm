package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（IR-08 子集闭合 / ENH-01）：Temporal 化后排查是异步的（202+轮询），
// Agent 必须能经 MCP 只读面查任务进度——否则 Harness 侧只能猜，违 AX-3「一切可验证」。
// 越权口径与 search_assets 一致：主体 InScope 强制（AX-5 无特权路径）。
func newSweepServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	as := asset.NewMemStore()
	_ = as.Create(ctx, asset.Asset{ID: "a1", Tenant: "t-a", Name: "backup.hddata.cn", Type: "domain",
		Risk: "high", Exp: 70, Owner: "运维", Found: time.Now(), Status: "在用", Beian: "已备案",
		Source: "P3/Dirsearch", Biz: "备份", IP: "192.168.1.7", Ports: []int{6379}, Tech: []string{"nginx"}})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-tb":    {UserID: "u2", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	sv := sweep.NewService(as, classify.New(), ledger.NewService(ledger.NewMemStore(), l))
	sw, err := sv.Execute(ctx, tokens["tok-admin"], "seed", "t-a", []string{"P1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(as, l), tokens, WithSweep(sv)).Handler())
	t.Cleanup(srv.Close)
	return srv, sw.ID
}

func TestGetSweepStatusTool(t *testing.T) {
	srv, sid := newSweepServer(t)

	// ① 工具注册（条件面）
	out := rpc(t, srv.URL, "tools/list", nil, "tok-admin")
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "get_sweep_status") {
		t.Fatal("tools/list 应含 get_sweep_status")
	}
	// ② 正常读取：状态+发现数+步数（Temporal 轮询面等价物）
	txt := toolText(t, rpc(t, srv.URL, "tools/call", map[string]any{
		"name": "get_sweep_status", "arguments": map[string]any{"sweep_id": sid}}, "tok-admin"))
	if !strings.Contains(txt, `"status":"done"`) || !strings.Contains(txt, `"steps":4`) || !strings.Contains(txt, `"findings":2`) {
		t.Errorf("状态内容错误: %s", txt)
	}
	// ③ 越权：t-b 主体不得读 t-a 的 sweep（不泄露进度内容）
	forb := toolText(t, rpc(t, srv.URL, "tools/call", map[string]any{
		"name": "get_sweep_status", "arguments": map[string]any{"sweep_id": sid}}, "tok-tb"))
	if strings.Contains(forb, "done") || strings.Contains(forb, `"findings"`) {
		t.Errorf("越权读到进度: %s", forb)
	}
	// ④ 未知 id 明确报错（fail loud，不返回空对象）
	unk := toolText(t, rpc(t, srv.URL, "tools/call", map[string]any{
		"name": "get_sweep_status", "arguments": map[string]any{"sweep_id": "S-nope"}}, "tok-admin"))
	if !strings.Contains(unk, "not found") {
		t.Errorf("未知 id 应报错: %s", unk)
	}
}
