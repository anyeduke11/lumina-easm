package pgstore

import (
	"context"
	"os"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

// 为什么（010=通报材料与归属判据的持久事实源）：JSONB 往返必须字段完整（四类基线列表、
// 线索包 items/chains/scale 一项不丢——丢字段=丢取证要素）；「双连接=跨进程/重启视角」
// 验证 server 重启后新进程能水化基线、检索线索包；WORM 首次语义=重放同 package_id
// 不改写首份材料（通报材料被后续扫描悄悄改写是不可接受的）。
func TestDarkwebStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-darkweb"
	cleanup := func() {
		_, _ = db.sql.Exec(`DELETE FROM ownership_fingerprints WHERE tenant_id=$1`, tid)
		_, _ = db.sql.Exec(`DELETE FROM lead_packages WHERE tenant_id=$1`, tid)
	}
	cleanup()
	t.Cleanup(cleanup)

	// ① 基线写穿 + 独立连接水化（=跨进程恢复判据）
	fp := ownership.Fingerprints{
		CertFPs:       []string{"AA:BB:CC", "DD:EE"},
		PageHashes:    []string{"9f2c"},
		NamingRules:   []string{"hdws_", "HDDC-"},
		FieldFeatures: []string{"cust_id_no", "acct_bank_code"},
	}
	if err := db.Darkweb().Save(ctx, tid, fp); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dsn) // 第二连接=新进程视角
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	m, err := db2.Darkweb().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := m[tid]
	if !ok || len(got.CertFPs) != 2 || got.NamingRules[1] != "HDDC-" || len(got.FieldFeatures) != 2 {
		t.Errorf("基线 JSONB 往返失真/水化缺失: %+v", got)
	}

	// ② 线索包写入 + 跨连接取回（items 取证要素完整）
	pkg := darkweb.LeadPackage{
		PackageID: "LPK-itest-1", TenantID: tid, GeneratedAt: "2026-10-17T00:00:00Z",
		ContentHash: "abc123",
		EvidenceRef: "file://itest/pkg.json",
		Items:       []darkweb.LeadItem{{SampleID: "S1", Source: "暗市", PostURL: "http://x.onion/1", CapturedAt: "2026-10-17T00:00:00Z", SampleHash: "h1", Verdict: "归属", Confidence: 0.9}},
		Chains:      []darkweb.Chain{{ID: "chain-S1", Members: []string{"S1"}, Size: 1}},
		Scale:       darkweb.ScaleEstimate{Low: 100, High: 5000, Confidence: 0.6, Method: "itest"},
	}
	if err := db.Darkweb().SavePackage(ctx, pkg); err != nil {
		t.Fatal(err)
	}
	g, ok, err := db2.Darkweb().GetPackage(ctx, tid, "LPK-itest-1")
	if !ok || err != nil {
		t.Fatalf("跨连接取回失败: %v %v", ok, err)
	}
	if len(g.Items) != 1 || g.Items[0].SampleHash != "h1" || g.Items[0].CapturedAt != "2026-10-17T00:00:00Z" ||
		g.Scale.High != 5000 || g.Chains[0].Members[0] != "S1" || g.ContentHash != "abc123" {
		t.Errorf("线索包往返字段失真: %+v", g)
	}

	// ③ WORM 首次：同 package_id 重写不改（篡改材料路径被挡）
	pkg2 := pkg
	pkg2.ContentHash = "EVIL-REWRITE"
	if err := db.Darkweb().SavePackage(ctx, pkg2); err != nil {
		t.Fatal(err)
	}
	g2, _, _ := db2.Darkweb().GetPackage(ctx, tid, "LPK-itest-1")
	if g2.ContentHash != "abc123" {
		t.Errorf("重放改写了首份通报材料（WORM 破坏）: %s", g2.ContentHash)
	}

	// ④ 跨租户不可见 + 按租户列举
	if _, ok, _ := db2.Darkweb().GetPackage(ctx, "itest-other", "LPK-itest-1"); ok {
		t.Error("跨租户不得取回他方线索包")
	}
	list, err := db2.Darkweb().ListPackages(ctx, tid)
	if err != nil || len(list) != 1 {
		t.Errorf("按租户列举错误: %v %v", err, list)
	}
}
