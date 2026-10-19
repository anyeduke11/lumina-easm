package graph

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 测试用确定性图（与 PG 侧集成测试同图，便于双后端契约对账）：
//
//	d1(Domain) → ip1(IPBlock) → app1(WebApp) → cred1(Credential)
//	                                        └→ ba1(BusinessAsset)
//	另有一条直达边 d1 → cred1（用于验证最短路径取 1 跳而非 3 跳）
func fixture() ([]Entity, []Relation) {
	ts := time.Unix(0, 0).UTC()
	ent := func(kind, fp string) Entity {
		return Entity{Kind: kind, Tenant: "t-a", Fingerprint: fp, Props: map[string]string{"name": fp},
			FirstSeen: ts, LastSeen: ts, InScope: true, Sources: []string{"test"}}
	}
	ents := []Entity{
		ent(KindDomain, "d1"), ent(KindIPBlock, "ip1"), ent(KindWebApp, "app1"),
		ent(KindCredential, "cred1"), ent(KindBusinessAsset, "ba1"),
	}
	rel := func(typ, from, to string) Relation {
		return Relation{Tenant: "t-a", Type: typ, FromFP: from, ToFP: to, TS: ts}
	}
	rels := []Relation{
		rel(RelResolvesTo, "d1", "ip1"), rel(RelHosts, "ip1", "app1"),
		rel(RelUses, "app1", "cred1"), rel(RelDependsOn, "app1", "ba1"),
		rel(RelLeaks, "d1", "cred1"), // 直达边（最短路径应走此边）
	}
	return ents, rels
}

type src struct {
	ents []Entity
	rels []Relation
}

func (s src) Entities(_ context.Context, _ string) ([]Entity, error)    { return s.ents, nil }
func (s src) Relations(_ context.Context, _ string) ([]Relation, error) { return s.rels, nil }

// 为什么（FR-GPH-004 / M3-B）：最短路径必须真最短——直达边存在时不得绕远，
// 且含边序列与缓解建议（路径可复现、可处置）。
func TestShortestPathPrefersDirectEdge(t *testing.T) {
	ents, rels := fixture()
	p := NewMemPath(src{ents, rels})
	edges, err := p.ShortestPath(context.Background(), "t-a", "d1", "cred1")
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].Type != RelLeaks {
		t.Errorf("应取 1 跳直达边 leaks: %+v", edges)
	}
}

func TestReachableRespectsDepth(t *testing.T) {
	ents, rels := fixture()
	p := NewMemPath(src{ents, rels})
	ok, edges, err := p.Reachable(context.Background(), "t-a", "d1", "ba1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("d1→ba1 需 3 跳，深度上限 2 应不可达: %+v", edges)
	}
	ok2, edges2, err := p.Reachable(context.Background(), "t-a", "d1", "ba1", 3)
	if err != nil || !ok2 || len(edges2) != 3 {
		t.Errorf("深度 3 应可达且 3 条边: %v %+v %v", ok2, edges2, err)
	}
	ok3, _, _ := p.Reachable(context.Background(), "t-a", "ba1", "d1", 3)
	if ok3 {
		t.Error("反向不可达（有向图语义）")
	}
}

func TestSubgraphByDepth(t *testing.T) {
	ents, rels := fixture()
	p := NewMemPath(src{ents, rels})
	e1, r1, err := p.Subgraph(context.Background(), "t-a", "ip1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(e1) != 2 || len(r1) != 1 {
		t.Errorf("depth1 应含 ip1+app1 与 1 条边: %d 实体 %d 边", len(e1), len(r1))
	}
	e2, r2, err := p.Subgraph(context.Background(), "t-a", "ip1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(e2) != 4 || len(r2) != 3 {
		t.Errorf("depth2 应含 4 实体 3 边: %d %d", len(e2), len(r2))
	}
}

// 为什么（Top5 可解释）：Top 路径必须确定性排序（hop→目标种类优先级→指纹字典序），
// 且每条路径带缓解建议与入选理由（不是黑盒排序）。
func TestTopPathsDeterministicAndExplained(t *testing.T) {
	ents, rels := fixture()
	p := NewMemPath(src{ents, rels})
	got1, err := p.TopPaths(context.Background(), "t-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got1) != 2 {
		t.Fatalf("Top2 应 2 条: %d", len(got1))
	}
	// 排序：最短优先——直达边 d1-leaks->cred1（1 跳）先于 ip1→cred1（2 跳）
	if got1[0].Hops != 1 || got1[0].ToFP != "cred1" || got1[0].Hops > got1[1].Hops {
		t.Errorf("排序应优先最短: %+v / %+v", got1[0], got1[1])
	}
	for _, pt := range got1 {
		if len(pt.Edges) != pt.Hops {
			t.Errorf("边序列与跳数不符: %s", pt.FromFP)
		}
		if len(pt.Mitigations) != pt.Hops || pt.Rationale == "" {
			t.Errorf("路径缺缓解建议/理由（不可处置）: %+v", pt)
		}
	}
	// 同跳数下目标种类优先级：Credential 先于 BusinessAsset（取 2 跳档验证）
	all, _ := p.TopPaths(context.Background(), "t-a", 10)
	var two []Path
	for _, pt := range all {
		if pt.Hops == 2 {
			two = append(two, pt)
		}
	}
	if len(two) >= 2 && two[0].ToKind != KindCredential {
		t.Errorf("同跳数下 Credential 应优先: %+v", two[0])
	}
	// 确定性：源数据顺序打乱后结果不变
	shuffled := []Relation{rels[3], rels[0], rels[4], rels[2], rels[1]}
	got2, _ := NewMemPath(src{ents, shuffled}).TopPaths(context.Background(), "t-a", 2)
	if len(got2) != len(got1) || got2[0].FromFP != got1[0].FromFP || got2[0].ToFP != got1[0].ToFP {
		t.Errorf("打乱源顺序后 Top 结果不稳定: %+v vs %+v", got2, got1)
	}
	// limit 收敛
	lim, _ := p.TopPaths(context.Background(), "t-a", 5)
	if len(lim) > 5 {
		t.Errorf("Top5 上限被突破: %d", len(lim))
	}
}

// 为什么（双后端契约核）：RankPaths 是 MemPath/PGPath 共用的排序去重函数——
// 同 (起点,终点) 必须保留**最短**路径（PG 递归 CTE 会枚举出多条同端点路径，
// 若退化成「保留最长/先到先得」，切后端即换结论，违反 AX-3 可复现）。
func TestRankPathsKeepsShortestPerEndpointPair(t *testing.T) {
	ents, rels := fixture()
	short := Path{FromFP: "d1", ToFP: "cred1", ToKind: KindCredential, FromKind: KindDomain, Hops: 1,
		Nodes: []string{"d1", "cred1"}, Edges: []Relation{rels[4]}, Mitigations: []string{Mitigation(RelLeaks)}}
	long := Path{FromFP: "d1", ToFP: "cred1", ToKind: KindCredential, FromKind: KindDomain, Hops: 3,
		Nodes: []string{"d1", "ip1", "app1", "cred1"}}
	got := RankPaths([]Path{long, short}, 10)
	if len(got) != 1 {
		t.Fatalf("同端点路径应去重为 1 条: %d", len(got))
	}
	if got[0].Hops != 1 {
		t.Errorf("应保留最短路径: hops=%d", got[0].Hops)
	}
	// 顺序无关（长路径先入参仍取短）
	got2 := RankPaths([]Path{short, long}, 10)
	if got2[0].Hops != 1 {
		t.Errorf("入参顺序不应影响最短保留: hops=%d", got2[0].Hops)
	}
	_ = ents
}

// 为什么：缓解建议按边类型给（可处置面），不得为空文案。
func TestMitigationCoversRelTypes(t *testing.T) {
	for _, r := range []string{RelOwns, RelResolvesTo, RelHosts, RelServes, RelUses,
		RelAffects, RelLeaks, RelValidOn, RelReachable, RelDependsOn, RelObserved} {
		m := Mitigation(r)
		if strings.TrimSpace(m) == "" {
			t.Errorf("关系 %s 缺缓解建议", r)
		}
	}
}
