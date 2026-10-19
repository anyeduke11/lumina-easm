package pgstore

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/ingest"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（FR-DSC-012 / AX-1）：入账资产必须同步投影到图谱——
// 若 main 接线漏了 SetAssetSync，或投影静默失败，台账会领先于图谱（事实源分叉）。
// 本用例走「真 asset.Service + 真投影 + 真 PGGraph」整链路，断言节点确已落库。
func TestAssetCreateProjectsToGraph(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	l := &audit.MemLog{}

	seedTenant(t, db.Tenants(), "itest-pt")
	gg := db.Graph()
	svc := asset.NewService(db.Assets(), l)
	svc.SetAssetSync(ingest.NewProjector(graph.NewService(gg)).Sync)

	r1 := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"itest-pt"}}
	a := asset.Asset{
		ID: "itest-proj-1", Tenant: "itest-pt", Name: "p.hddata.cn", Type: "domain", TypeLabel: "域名",
		Risk: "high", Exp: 55, Owner: "运维", Found: time.Now().UTC(),
		Status: "在用", Beian: "已备案", Source: "P2/Fofa", Biz: "门户", IP: "9.9.9.9",
	}
	if _, err := svc.Create(ctx, r1, "req-proj", a); err != nil {
		t.Fatalf("入账应成功: %v", err)
	}

	fp := ingest.FingerprintForAsset(a)
	if fp == "" {
		t.Fatal("应能算出指纹")
	}
	if _, found, err := gg.FindByFingerprint(ctx, "itest-pt", fp); err != nil || !found {
		t.Errorf("域名实体应已投影到图谱 found=%v err=%v fp=%s", found, err, fp)
	}
	// IP 实体 + resolves_to 边也应存在
	ipfp := graph.Fingerprint(graph.KindIPBlock, map[string]string{"cidr": "9.9.9.9/32"})
	if _, found, _ := gg.FindByFingerprint(ctx, "itest-pt", ipfp); !found {
		t.Error("带 IP 域名应追加 IP 实体到图谱")
	}
	nb, _ := gg.Neighbors(ctx, "itest-pt", fp)
	if len(nb) != 1 {
		t.Errorf("应有一条 resolves_to 边，实际 %d", len(nb))
	}
}

// 投影失败（非法图数据）不应让台账静默领先——Create 必须返回错误（AX-1 fail loud）。
func TestAssetCreateFailsWhenProjectionFails(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	l := &audit.MemLog{}
	seedTenant(t, db.Tenants(), "itest-pf")

	svc := asset.NewService(db.Assets(), l)
	svc.SetAssetSync(func(context.Context, asset.Asset) error {
		return context.DeadlineExceeded // 模拟投影故障
	})
	r1 := rbac.Principal{UserID: "u1", Role: "R1", TenantIDs: []string{"itest-pf"}}
	a := asset.Asset{ID: "itest-pf-1", Tenant: "itest-pf", Name: "z.hddata.cn", Type: "domain",
		TypeLabel: "域名", Risk: "low", Exp: 10, Owner: "运维", Found: time.Now().UTC(),
		Status: "在用", Beian: "已备案", Source: "P1/百度", Biz: "测试"}
	if _, err := svc.Create(ctx, r1, "req-pf", a); err == nil {
		t.Error("投影失败时 Create 必须返回错误，不得静默")
	}
}
