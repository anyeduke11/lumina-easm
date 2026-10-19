package ingest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// memGraph 同时实现 graph.Store 与 Reader，供单测。
type memGraph struct {
	mu    sync.Mutex
	nodes map[string]graph.Entity // key: tenant|fp
	edges []graph.Relation
}

func newMemGraph() *memGraph { return &memGraph{nodes: map[string]graph.Entity{}} }

func (m *memGraph) FindByFingerprint(_ context.Context, tenant, fp string) (graph.Entity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.nodes[tenant+"|"+fp]
	return e, ok, nil
}

func (m *memGraph) SaveEntity(_ context.Context, e graph.Entity, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[e.Tenant+"|"+e.Fingerprint] = e
	return nil
}

func (m *memGraph) UpsertRelation(_ context.Context, rel graph.Relation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.edges {
		if ex.Tenant == rel.Tenant && ex.Type == rel.Type && ex.FromFP == rel.FromFP && ex.ToFP == rel.ToFP {
			return nil
		}
	}
	// 端点存在性
	if _, ok := m.nodes[rel.Tenant+"|"+rel.FromFP]; !ok {
		return graph.ErrEndpoints
	}
	if _, ok := m.nodes[rel.Tenant+"|"+rel.ToFP]; !ok {
		return graph.ErrEndpoints
	}
	m.edges = append(m.edges, rel)
	return nil
}

func (m *memGraph) Neighbors(_ context.Context, tenant, fp string) ([]graph.Relation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []graph.Relation
	for _, e := range m.edges {
		if e.Tenant == tenant && (e.FromFP == fp || e.ToFP == fp) {
			out = append(out, e)
		}
	}
	return out, nil
}

func domAsset(ip string) asset.Asset {
	return asset.Asset{
		ID: "d1", Tenant: "t-a", Name: "a.hddata.cn", Type: "domain",
		Risk: "high", Exp: 60, Owner: "运维", Found: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Status: "在用", Beian: "已备案", Source: "P2/Fofa", Biz: "门户", IP: ip,
	}
}

// 为什么（FR-DSC-012 / AX-1）：入账资产必须投影为同指纹图谱实体——
// 若 mapKind 或 fingerprint 口径漂移，台账与图谱会静默分叉。
func TestSyncProjectsDomainAndIPWithEdge(t *testing.T) {
	mg := newMemGraph()
	gs := graph.NewService(mg)
	p := NewProjector(gs)

	if err := p.Sync(context.Background(), domAsset("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	dfp := graph.Fingerprint(graph.KindDomain, map[string]string{"value": "a.hddata.cn"})
	if _, ok, _ := mg.FindByFingerprint(context.Background(), "t-a", dfp); !ok {
		t.Errorf("域名实体应存在，指纹 %s", dfp)
	}
	ipfp := graph.Fingerprint(graph.KindIPBlock, map[string]string{"cidr": "1.2.3.4/32"})
	if _, ok, _ := mg.FindByFingerprint(context.Background(), "t-a", ipfp); !ok {
		t.Error("带 IP 的域名应追加 IP 实体")
	}
	nb, _ := mg.Neighbors(context.Background(), "t-a", dfp)
	if len(nb) != 1 || nb[0].Type != graph.RelResolvesTo {
		t.Errorf("应有一条 resolves_to 边，实际 %+v", nb)
	}
}

// web 资产带 IP 同样应连边（台账 web 形态常见）。
func TestSyncWebWithIPLinks(t *testing.T) {
	mg := newMemGraph()
	p := NewProjector(graph.NewService(mg))
	a := domAsset("1.2.3.4")
	a.Type = "web"
	if err := p.Sync(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	wfp := FingerprintForAsset(a)
	nb, _ := mg.Neighbors(context.Background(), "t-a", wfp)
	if len(nb) != 1 || nb[0].Type != graph.RelResolvesTo {
		t.Errorf("web+IP 应有 resolves_to 边，实际 %+v", nb)
	}
}

// 无 IP 时不应产生 IP 实体/边。
func TestSyncDomainWithoutIP(t *testing.T) {
	mg := newMemGraph()
	p := NewProjector(graph.NewService(mg))
	if err := p.Sync(context.Background(), domAsset("")); err != nil {
		t.Fatal(err)
	}
	if len(mg.edges) != 0 {
		t.Errorf("无 IP 不应有边，实际 %d", len(mg.edges))
	}
}

// 未映射类型不投影也不报错（M1 由 parser 承接）。
func TestSyncUnmappedTypeSkipped(t *testing.T) {
	mg := newMemGraph()
	p := NewProjector(graph.NewService(mg))
	a := domAsset("")
	a.Type = "cloud"
	if err := p.Sync(context.Background(), a); err != nil {
		t.Errorf("未映射类型应跳过不报错: %v", err)
	}
	if len(mg.nodes) != 0 {
		t.Errorf("未映射类型不应写节点，实际 %d", len(mg.nodes))
	}
}

// FingerprintForAsset 与投影同口径（供 IR-06 按资产查图谱）。
func TestFingerprintForAssetConsistentWithProjection(t *testing.T) {
	mg := newMemGraph()
	p := NewProjector(graph.NewService(mg))
	a := domAsset("")
	if err := p.Sync(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	fp := FingerprintForAsset(a)
	if fp == "" {
		t.Fatal("应能算出指纹")
	}
	if _, ok, _ := mg.FindByFingerprint(context.Background(), a.Tenant, fp); !ok {
		t.Errorf("FingerprintForAsset 必须命中投影写入的同一节点: %s", fp)
	}
}
