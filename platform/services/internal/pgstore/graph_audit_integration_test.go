package pgstore

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// MVP 图谱：实体 upsert/merge 与边引用完整性走真 PG（同 DSN 前置条件）。
func TestPGGraphUpsertMergeAndEdges(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	g := db.Graph()

	seedTenant(t, db.Tenants(), "itest-gt")
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	later := base.AddDate(0, 0, 3)

	e1 := graph.Entity{Kind: graph.KindDomain, Tenant: "itest-gt",
		Props: map[string]string{"value": "a.hddata.cn"}, FirstSeen: base, LastSeen: base,
		Sources: []string{"subfinder"}}
	svc := graph.NewService(g)
	_, created, err := svc.UpsertEntity(ctx, e1)
	if err != nil || !created {
		t.Fatalf("首次应新建: created=%v err=%v", created, err)
	}

	e2 := e1
	e2.Props = map[string]string{"value": "A.HDDATA.CN"} // 归一后同指纹
	e2.LastSeen = later
	e2.Sources = []string{"fofa"}
	_, created, err = svc.UpsertEntity(ctx, e2)
	if err != nil || created {
		t.Fatalf("二次应 merge: created=%v err=%v", created, err)
	}
	got, found, err := g.FindByFingerprint(ctx, "itest-gt", "dom:a.hddata.cn")
	if err != nil || !found {
		t.Fatalf("回读失败: %v", err)
	}
	if len(got.Sources) != 2 {
		t.Errorf("sources 应并集去重，实际 %v", got.Sources)
	}
	if !got.LastSeen.Equal(later) || !got.FirstSeen.Equal(base) {
		t.Errorf("first/last_seen 窗口错误: %v %v", got.FirstSeen, got.LastSeen)
	}

	// 边：端点齐备成功；缺端点必须 ErrEndpoints（引用完整性）
	webFP := graph.Fingerprint(graph.KindWebApp, map[string]string{"url": "https://a.hddata.cn"})
	if _, _, err := svc.UpsertEntity(ctx, graph.Entity{Kind: graph.KindWebApp, Tenant: "itest-gt",
		Props: map[string]string{"url": "https://a.hddata.cn"}, FirstSeen: base, LastSeen: base,
		Sources: []string{"httpx"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpsertRelation(ctx, graph.Relation{Tenant: "itest-gt", Type: graph.RelResolvesTo,
		FromFP: "dom:a.hddata.cn", ToFP: webFP, TS: base}); err != nil {
		t.Fatalf("合法边应成功: %v", err)
	}
	if err := svc.UpsertRelation(ctx, graph.Relation{Tenant: "itest-gt", Type: graph.RelHosts,
		FromFP: "dom:a.hddata.cn", ToFP: "ip:9.9.9.9/tcp/80", TS: base}); err != graph.ErrEndpoints {
		t.Errorf("缺端点应 ErrEndpoints，实际 %v", err)
	}
	nb, err := g.Neighbors(ctx, "itest-gt", "dom:a.hddata.cn")
	if err != nil || len(nb) != 1 {
		t.Errorf("一跳邻接应 1 条，实际 %d err=%v", len(nb), err)
	}
}

// 为什么（NFR-SEC-006）：审计必须真的落库且可按租户读回；
// 若 Append 静默吞错，取证链断裂——用例断言行存在。
func TestPGAuditAppendAndReadBack(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	a := db.Audit()

	err := a.Append(ctx, audit.Entry{Actor: "itest", Action: "itest.action", TenantID: "itest-gt",
		Resource: "r-1", Result: audit.ResultDeny, RequestID: "req-itest"})
	if err != nil {
		t.Fatalf("审计写入失败: %v", err)
	}
	out, err := a.Recent(ctx, "itest-gt", 10)
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, e := range out {
		if e.Action == "itest.action" && e.Result == audit.ResultDeny && e.RequestID == "req-itest" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("应读回刚写入的审计条目，实际 %d 条", len(out))
	}
}
