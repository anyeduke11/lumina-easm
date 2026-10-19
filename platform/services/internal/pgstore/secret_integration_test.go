package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
)

// 集成替身：固定返回 200（不发起真实外呼——集成测试不依赖外网）。
type fixedProber struct{ status int }

func (f fixedProber) Probe(context.Context, secret.Entry) (secret.ProbeResult, error) {
	return secret.ProbeResult{Reached: true, Status: f.status}, nil
}

// 为什么（C-6 双后端同契约）：M3-C 的判定入图与度量读回在 PG（递归/表）与内存
// （map）两条路径上必须给出**同一度量**——否则「切后端=换误报率」，FR-CHN-002 的
// 度量基线不可信。本节同时验证 PG 侧新加的 graph 实体枚举（Entities）契约。
func TestSecretMetricsBothBackendsAgree(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("需要 EASM_PG_DSN")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-secret"
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO tenants (id, name, status) VALUES ($1,'密钥度量租户','active')
		ON CONFLICT (id) DO NOTHING`, tid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_edges WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM graph_nodes WHERE tenant_id=$1`, tid)
		_, _ = db.sql.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tid)
	})
	ts := time.Unix(0, 0).UTC()
	dom := graph.Entity{Kind: graph.KindDomain, Tenant: tid, Fingerprint: "dom:s.example.cn",
		Props: map[string]string{"value": "s.example.cn"}, FirstSeen: ts, LastSeen: ts, InScope: true}
	// 内存侧同样预置（同一初始状态）
	gms := graph.NewMemStore()
	pgSvc, memSvc := secret.New().WithGraph(graph.NewService(db.Graph())).WithProber(fixedProber{200}),
		secret.New().WithGraph(graph.NewService(gms)).WithProber(fixedProber{200})
	if _, _, err := graph.NewService(db.Graph()).UpsertEntity(ctx, dom); err != nil {
		t.Fatal(err)
	}
	if _, _, err := graph.NewService(gms).UpsertEntity(ctx, dom); err != nil {
		t.Fatal(err)
	}
	entries := []secret.Entry{
		{Tenant: tid, Rule: secret.RuleKey, Location: "a.js#L1", Snippet: "AKIAIOSFODNN7EXAMPLE",
			ProbeURL: "https://api.example.com/v1", SourceFP: "dom:s.example.cn"},
		{Tenant: tid, Rule: secret.RuleKey, Location: "b.js#L2", Snippet: "AKIA1234",
			SourceFP: "dom:s.example.cn"},
		{Tenant: tid, Rule: secret.RuleHardcode, Location: "c.js#L3", Snippet: "changeme"},
	}
	pgV, err := pgSvc.Verify(ctx, tid, entries)
	if err != nil {
		t.Fatal(err)
	}
	memV, err := memSvc.Verify(ctx, tid, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(pgV) != len(memV) || len(pgV) != 3 {
		t.Fatalf("判定条数不符: pg=%d mem=%d", len(pgV), len(memV))
	}
	for i := range pgV {
		if pgV[i].Status != memV[i].Status || pgV[i].Method != memV[i].Method || pgV[i].Linked != memV[i].Linked {
			t.Errorf("判定[%d] 双后端不一致: pg=%s/%s/link=%v mem=%s/%s/link=%v", i,
				pgV[i].Status, pgV[i].Method, pgV[i].Linked,
				memV[i].Status, memV[i].Method, memV[i].Linked)
		}
	}
	if !pgV[0].Linked || pgV[1].Linked || pgV[2].Linked {
		t.Errorf("仅验证为可用的凭据应连边: %v/%v/%v", pgV[0].Linked, pgV[1].Linked, pgV[2].Linked)
	}
	pgM, err := pgSvc.Metrics(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	memM, err := memSvc.Metrics(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if pgM.Total != memM.Total || pgM.Total != 3 {
		t.Errorf("度量总数不符: pg=%d mem=%d", pgM.Total, memM.Total)
	}
	if pgM.ByStatus[secret.StatusValid] != memM.ByStatus[secret.StatusValid] ||
		pgM.ByStatus[secret.StatusInvalid] != memM.ByStatus[secret.StatusInvalid] {
		t.Errorf("度量分布不符: pg=%+v mem=%+v", pgM.ByStatus, memM.ByStatus)
	}
	if pgM.Probed != 1 || pgM.ProbeConfirmed != 1 {
		t.Errorf("PG 侧探活统计不符: %d/%d", pgM.Probed, pgM.ProbeConfirmed)
	}
	// 图谱边供给（M3-B 缺口闭合）：PG 侧应能推演出 1 跳攻击路径
	paths, err := db.GraphPath().TopPaths(ctx, tid, 5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range paths {
		if p.FromFP == "dom:s.example.cn" && p.ToKind == graph.KindCredential && p.Hops == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("PG 侧应产出凭据攻击路径: %+v", paths)
	}
}
