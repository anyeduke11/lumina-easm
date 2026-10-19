package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// 为什么（M3-B 双后端契约）：同一图在 MemPath（Go BFS）与 PGPath（递归 CTE）下
// 必须给出**同一 TopN 与同一最短路径**——否则「切后端=换结论」，违反 AX-3 可复现。
func TestPathQueryBothBackendsAgree(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("需要 EASM_PG_DSN")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-path"
	g := db.Graph()
	// 建租户（外键约束）
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO tenants (id, name, status) VALUES ($1,'路径对账租户','active')
		ON CONFLICT (id) DO NOTHING`, tid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_edges WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_nodes WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tid)
	})

	ts := time.Unix(0, 0).UTC()
	ents := []graph.Entity{
		{Kind: graph.KindDomain, Tenant: tid, Fingerprint: "d1", Props: map[string]string{}, FirstSeen: ts, LastSeen: ts, InScope: true},
		{Kind: graph.KindIPBlock, Tenant: tid, Fingerprint: "ip1", Props: map[string]string{}, FirstSeen: ts, LastSeen: ts, InScope: true},
		{Kind: graph.KindWebApp, Tenant: tid, Fingerprint: "app1", Props: map[string]string{}, FirstSeen: ts, LastSeen: ts, InScope: true},
		{Kind: graph.KindCredential, Tenant: tid, Fingerprint: "cred1", Props: map[string]string{}, FirstSeen: ts, LastSeen: ts, InScope: true},
		{Kind: graph.KindBusinessAsset, Tenant: tid, Fingerprint: "ba1", Props: map[string]string{}, FirstSeen: ts, LastSeen: ts, InScope: true},
	}
	for _, e := range ents {
		if err := g.SaveEntity(ctx, e, true); err != nil {
			t.Fatal(err)
		}
	}
	rels := []graph.Relation{
		{Tenant: tid, Type: graph.RelResolvesTo, FromFP: "d1", ToFP: "ip1", TS: ts},
		{Tenant: tid, Type: graph.RelHosts, FromFP: "ip1", ToFP: "app1", TS: ts},
		{Tenant: tid, Type: graph.RelUses, FromFP: "app1", ToFP: "cred1", TS: ts},
		{Tenant: tid, Type: graph.RelDependsOn, FromFP: "app1", ToFP: "ba1", TS: ts},
		{Tenant: tid, Type: graph.RelLeaks, FromFP: "d1", ToFP: "cred1", TS: ts},
	}
	mem := graph.NewMemStore()
	for _, e := range ents {
		_ = mem.SaveEntity(ctx, e, true)
	}
	for _, r := range rels {
		if err := g.UpsertRelation(ctx, r); err != nil {
			t.Fatal(err)
		}
		_ = mem.UpsertRelation(ctx, r)
	}
	pg := db.GraphPath()
	memPath := graph.NewMemPath(mem)

	// 最短路径一致
	pgEdges, err := pg.ShortestPath(ctx, tid, "d1", "cred1")
	if err != nil {
		t.Fatal(err)
	}
	memEdges, err := memPath.ShortestPath(ctx, tid, "d1", "cred1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pgEdges) != len(memEdges) || len(memEdges) == 0 || pgEdges[0].Type != memEdges[0].Type {
		t.Errorf("最短路径双后端不一致: pg=%+v mem=%+v", pgEdges, memEdges)
	}

	// 可达性（深度受限）一致
	okPG, _, err := pg.Reachable(ctx, tid, "d1", "ba1", 2)
	if err != nil {
		t.Fatal(err)
	}
	okMem, _, _ := memPath.Reachable(ctx, tid, "d1", "ba1", 2)
	if okPG != okMem {
		t.Errorf("可达性双后端不一致: pg=%v mem=%v", okPG, okMem)
	}
	okPG2, _, _ := pg.Reachable(ctx, tid, "d1", "ba1", 3)
	okMem2, _, _ := memPath.Reachable(ctx, tid, "d1", "ba1", 3)
	if !okPG2 || !okMem2 {
		t.Errorf("深度 3 应双后端均可达: pg=%v mem=%v", okPG2, okMem2)
	}

	// TopN 一致（顺序+跳数+端点）
	pgTop, err := pg.TopPaths(ctx, tid, 3)
	if err != nil {
		t.Fatal(err)
	}
	memTop, err := memPath.TopPaths(ctx, tid, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pgTop) != len(memTop) {
		t.Fatalf("TopN 数量不一致: pg=%d mem=%d", len(pgTop), len(memTop))
	}
	for i := range pgTop {
		if pgTop[i].FromFP != memTop[i].FromFP || pgTop[i].ToFP != memTop[i].ToFP || pgTop[i].Hops != memTop[i].Hops {
			t.Errorf("TopN[%d] 不一致: pg=%s→%s(%d) mem=%s→%s(%d)", i,
				pgTop[i].FromFP, pgTop[i].ToFP, pgTop[i].Hops,
				memTop[i].FromFP, memTop[i].ToFP, memTop[i].Hops)
		}
	}

	// 子图一致（实体集合）
	pgE, pgR, err := pg.Subgraph(ctx, tid, "ip1", 1)
	if err != nil {
		t.Fatal(err)
	}
	memE, memR, _ := memPath.Subgraph(ctx, tid, "ip1", 1)
	if len(pgE) != len(memE) || len(pgR) != len(memR) {
		t.Errorf("子图不一致: pg=%d实体/%d边 mem=%d实体/%d边", len(pgE), len(pgR), len(memE), len(memR))
	}
}

// 为什么（fail loud 优于兜底）：路径枚举超上限必须**报错**，不得静默截断——
// 静默截断会让 TopN 悄悄少给路径（看起来「就这些」），切图规模后结论不可比。
func TestPathEnumerationOverflowFailsLoud(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("需要 EASM_PG_DSN")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-path2"
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO tenants (id, name, status) VALUES ($1,'路径溢出租户','active')
		ON CONFLICT (id) DO NOTHING`, tid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_edges WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_nodes WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tid)
	})
	ts := time.Unix(0, 0).UTC()
	ent := func(kind, fp string) graph.Entity {
		return graph.Entity{Kind: kind, Tenant: tid, Fingerprint: fp, Props: map[string]string{},
			FirstSeen: ts, LastSeen: ts, InScope: true}
	}
	g := db.Graph()
	for _, fp := range []string{"od1", "oi1", "oi2", "oi3", "oc1"} {
		kind := graph.KindDomain
		switch fp {
		case "oi1", "oi2", "oi3":
			kind = graph.KindIPBlock
		case "oc1":
			kind = graph.KindCredential
		}
		if err := g.SaveEntity(ctx, ent(kind, fp), true); err != nil {
			t.Fatal(err)
		}
	}
	// 3 条入口→IP→凭据的两跳路径（枚举 6 行 > 上限 3）
	for _, ip := range []string{"oi1", "oi2", "oi3"} {
		if err := g.UpsertRelation(ctx, graph.Relation{Tenant: tid, Type: graph.RelResolvesTo, FromFP: "od1", ToFP: ip, TS: ts}); err != nil {
			t.Fatal(err)
		}
		if err := g.UpsertRelation(ctx, graph.Relation{Tenant: tid, Type: graph.RelUses, FromFP: ip, ToFP: "oc1", TS: ts}); err != nil {
			t.Fatal(err)
		}
	}
	old := maxPathRows
	maxPathRows = 3
	t.Cleanup(func() { maxPathRows = old })
	got, err := db.GraphPath().TopPaths(ctx, tid, 5)
	if err == nil {
		t.Errorf("枚举超上限应报错上浮，实际返回 %d 条路径", len(got))
	}
	if got != nil {
		t.Error("报错时不得同时返回截断路径（不静默降级）")
	}
}
