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
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/ingest"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

type stubGraph struct {
	node graph.Entity
	rels []graph.Relation
}

func (g *stubGraph) EntityByFingerprint(_ context.Context, _, fp string) (graph.Entity, bool, error) {
	if g.node.Fingerprint == fp {
		return g.node, true, nil
	}
	return graph.Entity{}, false, nil
}

func (g *stubGraph) Neighbors(_ context.Context, _, fp string) ([]graph.Relation, error) {
	var out []graph.Relation
	for _, r := range g.rels {
		if r.FromFP == fp || r.ToFP == fp {
			out = append(out, r)
		}
	}
	return out, nil
}

func newGraphServer(t *testing.T) (*httptest.Server, *stubGraph) {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	tstore := tenant.NewMemStore()
	_ = tstore.Create(ctx, tenant.Tenant{ID: "t-a", Name: "a", Status: "active"})
	astore := asset.NewMemStore()
	seed := asset.Asset{ID: "dom-1", Tenant: "t-a", Name: "a.hddata.cn", Type: "domain",
		Risk: "high", Exp: 60, Owner: "运维", Found: time.Now(), Status: "在用",
		Beian: "已备案", Source: "P2/Fofa", Biz: "门户", IP: "1.2.3.4"}
	_ = astore.Create(ctx, seed)

	fp := ingest.FingerprintForAsset(seed)
	ipfp := graph.Fingerprint(graph.KindIPBlock, map[string]string{"cidr": "1.2.3.4/32"})
	sg := &stubGraph{
		node: graph.Entity{Kind: graph.KindDomain, Tenant: "t-a", Fingerprint: fp,
			Props: map[string]string{"value": "a.hddata.cn"}, FirstSeen: time.Now(), LastSeen: time.Now(),
			InScope: true, Sources: []string{"P2/Fofa"}},
		rels: []graph.Relation{{Tenant: "t-a", Type: graph.RelResolvesTo, FromFP: fp, ToFP: ipfp, TS: time.Now()}},
	}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-tb":    {UserID: "u1b", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(tstore, l), asset.NewService(astore, l), tokens, WithGraph(sg)).Handler())
	t.Cleanup(srv.Close)
	return srv, sg
}

func TestGraphEntityEndpoint(t *testing.T) {
	srv, _ := newGraphServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/graph/entities/dom-1", nil)
	req.Header.Set("Authorization", "Bearer tok-ta")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	ent, _ := out["entity"].(map[string]any)
	if ent["kind"] != graph.KindDomain {
		t.Errorf("实体 kind 应为 Domain，实际 %v", ent["kind"])
	}
	nb, _ := out["neighbors"].([]any)
	if len(nb) != 1 {
		t.Errorf("应返回 1 条一跳邻居，实际 %d", len(nb))
	}
}

// 为什么：按资产 id 查图谱必须先过资产鉴权——跨租户主体不得借图谱端点旁路读取他租实体。
func TestGraphEntityCrossTenantDenied(t *testing.T) {
	srv, _ := newGraphServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/graph/entities/dom-1", nil)
	req.Header.Set("Authorization", "Bearer tok-tb") // t-b 主体读 t-a 资产
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("跨租户图谱读取期望 403，实际 %d", resp.StatusCode)
	}
}

func TestGraphQueryScoped(t *testing.T) {
	srv, sg := newGraphServer(t)
	fp := sg.node.Fingerprint
	body, _ := json.Marshal(map[string]string{"tenant": "t-a", "fingerprint": fp})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/graph/query", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-ta")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("同租户查询期望 200，实际 %d", resp.StatusCode)
	}

	// 跨租户：t-b 主体查 t-a → 403
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/graph/query", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer tok-tb")
	resp2, err2 := http.DefaultClient.Do(req2)
	if err2 != nil {
		t.Fatal(err2)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("跨租户图谱查询期望 403，实际 %d", resp2.StatusCode)
	}
}
