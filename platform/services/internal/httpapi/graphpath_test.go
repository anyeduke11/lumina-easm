package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 内存图谱源（与 graph 包 fixture 同形）
type memSrc struct {
	ents []graph.Entity
	rels []graph.Relation
}

func (m memSrc) Entities(context.Context, string) ([]graph.Entity, error)    { return m.ents, nil }
func (m memSrc) Relations(context.Context, string) ([]graph.Relation, error) { return m.rels, nil }

func newPathServer(t *testing.T, withPaths bool) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ts := tenant.NewMemStore()
	_ = ts.Create(nil, tenant.Tenant{ID: "t-g", Name: "图谱租户", Status: "active"})
	tokens := map[string]rbac.Principal{"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}}
	opts := []Option{}
	if withPaths {
		opts = append(opts, WithPaths(graph.NewMemPath(memSrc{ents: ents(), rels: rels()})))
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(asset.NewMemStore(), l), tokens, opts...).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func ts0() time.Time { return time.Unix(0, 0).UTC() }

func ents() []graph.Entity {
	e := func(kind, fp string) graph.Entity {
		return graph.Entity{Kind: kind, Tenant: "t-g", Fingerprint: fp, Props: map[string]string{"name": fp},
			FirstSeen: ts0(), LastSeen: ts0(), InScope: true, Sources: []string{"test"}}
	}
	return []graph.Entity{e(graph.KindDomain, "d1"), e(graph.KindIPBlock, "ip1"),
		e(graph.KindWebApp, "app1"), e(graph.KindCredential, "cred1"), e(graph.KindBusinessAsset, "ba1")}
}

func rels() []graph.Relation {
	r := func(typ, from, to string) graph.Relation {
		return graph.Relation{Tenant: "t-g", Type: typ, FromFP: from, ToFP: to, TS: ts0()}
	}
	return []graph.Relation{r(graph.RelResolvesTo, "d1", "ip1"), r(graph.RelHosts, "ip1", "app1"),
		r(graph.RelUses, "app1", "cred1"), r(graph.RelDependsOn, "app1", "ba1"), r(graph.RelLeaks, "d1", "cred1")}
}

// 为什么（FR-GPH-004）：路径端点必须直出可复现边序与缓解建议；未装配=501（不伪造路径）。
func TestGraphPathEndpoints(t *testing.T) {
	srv := newPathServer(t, true)
	resp, body := get2(srv.URL+"/v1/tenants/t-g/graph/paths?from=d1&to=cred1", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("最短路径期望 200: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Hops        int              `json:"hops"`
		Reachable   bool             `json:"reachable"`
		Mitigations []string         `json:"mitigations"`
		Edges       []graph.Relation `json:"edges"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Hops != 1 || !out.Reachable || len(out.Edges) != 1 {
		t.Errorf("应 1 跳直达: %+v", out)
	}
	if len(out.Mitigations) != out.Hops || strings.TrimSpace(out.Mitigations[0]) == "" {
		t.Errorf("缺缓解建议: %+v", out.Mitigations)
	}

	// reach：深度受限
	_, b2 := get2(srv.URL+"/v1/tenants/t-g/graph/reach?from=d1&to=ba1&depth=2", "tok-admin")
	if strings.Contains(b2, `"reachable":true`) {
		t.Errorf("深度 2 应不可达: %s", b2)
	}
	_, b3 := get2(srv.URL+"/v1/tenants/t-g/graph/reach?from=d1&to=ba1&depth=3", "tok-admin")
	if !strings.Contains(b3, `"reachable":true`) {
		t.Errorf("深度 3 应可达: %s", b3)
	}
	// subgraph
	_, b4 := get2(srv.URL+"/v1/tenants/t-g/graph/subgraph?fp=ip1&depth=1", "tok-admin")
	if !strings.Contains(b4, "app1") || strings.Contains(b4, "cred1") {
		t.Errorf("depth1 子图应含 app1 不含 cred1: %s", b4[:min(200, len(b4))])
	}
	// top-paths
	_, b5 := get2(srv.URL+"/v1/tenants/t-g/graph/top-paths?limit=3", "tok-admin")
	if !strings.Contains(b5, "ranking") || !strings.Contains(b5, "cred1") {
		t.Errorf("Top 路径异常: %s", b5[:min(200, len(b5))])
	}
	// 参数校验
	r6, _ := get2(srv.URL+"/v1/tenants/t-g/graph/paths", "tok-admin")
	if r6.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 from/to 应 400: %d", r6.StatusCode)
	}
}

// 未装配=501（fail loud，不返回空路径冒充「无攻击路径」）
func TestGraphPathUnavailableIs501(t *testing.T) {
	srv := newPathServer(t, false)
	for _, path := range []string{
		"/v1/tenants/t-g/graph/paths?from=d1&to=cred1",
		"/v1/tenants/t-g/graph/reach?from=d1&to=ba1",
		"/v1/tenants/t-g/graph/subgraph?fp=ip1",
		"/v1/tenants/t-g/graph/top-paths",
	} {
		resp, body := get2(srv.URL+path, "tok-admin")
		if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "graph_path_unavailable") {
			t.Errorf("%s 应 501 graph_path_unavailable: %d %s", path, resp.StatusCode, body)
		}
	}
}
