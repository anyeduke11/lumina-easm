package httpapi

// 为什么（一票否决④ / FR-TEN-005）：平台级读端（sweeps/alerts/monitors/ownership/candidates）
// 必须按主体 entity 作用域过滤，越权读返回 403 且落 deny 审计——不静默返空、不跨域可见。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

func newScopeServer(t *testing.T) (*httptest.Server, *audit.MemLog) {
	t.Helper()
	ctx := context.Background()
	l := &audit.MemLog{}
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-b", Name: "乙", Status: "active"})
	ast := asset.NewMemStore()
	led := ledger.NewService(ledger.NewMemStore(), l)
	v, i := vuln.NewService(), intel.NewService()
	o := ownership.NewService()
	if _, err := o.AdmitOrQueue(ctx, "t-a", ownership.Verdict{Domain: "maybe-a.cn", Verdict: ownership.VerdictSuspect}, "maybe-a.cn"); err != nil {
		t.Fatalf("seed queue t-a: %v", err)
	}
	if _, err := o.AdmitOrQueue(ctx, "t-b", ownership.Verdict{Domain: "maybe-b.cn", Verdict: ownership.VerdictSuspect}, "maybe-b.cn"); err != nil {
		t.Fatalf("seed queue t-b: %v", err)
	}
	m := monitor.New(v, i, func() map[string][]asset.Asset { return nil })
	m.OnImport("vuln", map[string][]asset.Asset{
		"t-a": {{ID: "a-1", Tenant: "t-a", Name: "redis.a.cn", Tags: []string{"redis"}}},
		"t-b": {{ID: "b-1", Tenant: "t-b", Name: "redis.b.cn", Tags: []string{"redis"}}},
	})
	cands := candidate.NewService()
	if _, _, err := cands.Ingest(ctx, rbac.Principal{UserID: "seed", Role: "admin", TenantIDs: []string{"*"}}, "bad-scope-line"); err != nil {
		t.Fatalf("seed unsupported: %v", err)
	}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u-admin", Role: "admin", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u-a", Role: "R1", TenantIDs: []string{"t-a"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(ast, l), tokens,
		WithLedger(led), WithSweep(sweep.NewService(ast, classify.New(), led)),
		WithKnowledge(v, i, o), WithMonitor(m), WithCandidates(cands), WithAudit(l)).Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

func TestReadEndpointsScopeFilter(t *testing.T) {
	srv, logs := newScopeServer(t)

	_, bodyA := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-a","phases":["P1"]}`)
	_, bodyB := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-b","phases":["P1"]}`)
	var swA, swB sweep.Sweep
	_ = json.Unmarshal([]byte(bodyA), &swA)
	_ = json.Unmarshal([]byte(bodyB), &swB)
	if swA.ID == "" || swB.ID == "" {
		t.Fatalf("seed sweeps 失败: %s / %s", bodyA, bodyB)
	}

	// sweeps 列表：仅本域行；定向查他域与 Get 他域均 403
	resp, body := get2(srv.URL+"/v1/sweeps", "tok-ta")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, swA.ID) || strings.Contains(body, swB.ID) {
		t.Errorf("列表应仅含 t-a 行: %d %s", resp.StatusCode, body)
	}
	if resp, body = get2(srv.URL+"/v1/sweeps?tenant_id=t-b", "tok-ta"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("定向查他域应 403: %d %s", resp.StatusCode, body)
	}
	if resp, body = get2(srv.URL+"/v1/sweeps/"+swB.ID, "tok-ta"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("跨域 Get 应 403: %d %s", resp.StatusCode, body)
	}
	// 平台管理员（*）仍见全量
	if resp, body = get2(srv.URL+"/v1/sweeps", "tok-admin"); resp.StatusCode != http.StatusOK || !strings.Contains(body, swB.ID) {
		t.Errorf("管理域应见全量: %d %s", resp.StatusCode, body)
	}

	// alerts：行级租户过滤（vuln_match/intel_hit 均须带 TenantID）
	if resp, body = get2(srv.URL+"/v1/alerts", "tok-ta"); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, "redis.a.cn") || strings.Contains(body, "redis.b.cn") {
		t.Errorf("告警应仅含本域资产: %d %s", resp.StatusCode, body)
	}

	// ownership 复核队列：仅本域项
	if resp, body = get2(srv.URL+"/v1/ownership/queue", "tok-ta"); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, "maybe-a.cn") || strings.Contains(body, "maybe-b.cn") {
		t.Errorf("复核队列应仅含本域项: %d %s", resp.StatusCode, body)
	}

	// monitors（平台级配置读）与 unsupported（无租户字段）仅管理域可读
	if resp, body = get2(srv.URL+"/v1/monitors", "tok-ta"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("非管理域读监控器应 403: %d %s", resp.StatusCode, body)
	}
	if resp, body = get2(srv.URL+"/v1/candidates/unsupported", "tok-ta"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("非管理域读 unsupported 应 403: %d %s", resp.StatusCode, body)
	}
	if resp, body = get2(srv.URL+"/v1/candidates/unsupported", "tok-admin"); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, "bad-scope-line") {
		t.Errorf("管理域应见 unsupported 复核项: %d %s", resp.StatusCode, body)
	}

	// deny 审计：每个越权出口都必须留痕（actor/tenant/action）
	denied := map[string]audit.Entry{}
	for _, e := range logs.Snapshot() {
		if e.Result == audit.ResultDeny {
			denied[e.Action] = e
		}
	}
	for _, action := range []string{"sweep.list", "sweep.get", "monitor.list", "candidate.unsupported"} {
		e, ok := denied[action]
		if !ok {
			t.Errorf("缺少 deny 审计: %s", action)
			continue
		}
		if e.Actor != "u-a" || e.RequestID == "" {
			t.Errorf("deny 审计字段缺失: %+v", e)
		}
	}
	if e := denied["sweep.get"]; e.TenantID != "t-b" {
		t.Errorf("sweep.get deny 应记录目标租户 t-b: %+v", e)
	}
}
