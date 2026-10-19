package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
)

// 为什么（007 / ENH-01）：worker 进程必须读到 server 录入的 auth_scope（同库=同闸）；
// 同时 server 重启授权不丢。JSONB 往返必须保字段完整（C-6 双实现同契约）。
func TestAuthzStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM auth_scopes WHERE tenant_id='itest-authz'`) }
	cleanup()
	t.Cleanup(cleanup)

	sc := authz.Scope{
		Tenant: "itest-authz", Domains: []string{"hddata.cn"}, CIDRs: []string{"203.0.113.0/24"},
		Ports: []int{443, 8080}, Excludes: []string{"legacy.hddata.cn"},
		ValidFrom: time.Now().UTC().Add(-time.Hour), ValidTo: time.Now().UTC().Add(24 * time.Hour),
		RateLimit: 1000, TimeWindow: "00:00-08:00", SecondAuth: true,
		Signer: "法人章", DocHash: "sha256:test",
	}
	if err := db.Authz().Put(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.Authz().Get(ctx, "itest-authz")
	if !ok || err != nil {
		t.Fatalf("回读失败 %v %v", ok, err)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 443 || !got.SecondAuth || got.RateLimit != 1000 {
		t.Errorf("字段丢失: %+v", got)
	}
	if got.Excludes[0] != "legacy.hddata.cn" || got.DocHash != "sha256:test" || !got.ValidTo.After(got.ValidFrom) {
		t.Errorf("时间/数组字段往返失真: %+v", got)
	}
	// upsert 覆盖（撤回=改写语义）
	sc.ValidTo = sc.ValidFrom.Add(time.Second)
	if err := db.Authz().Put(ctx, sc); err != nil {
		t.Fatal(err)
	}
	g2, _, _ := db.Authz().Get(ctx, "itest-authz")
	if !g2.ValidTo.Before(time.Now().UTC()) {
		t.Error("授权改写未生效（撤回语义破坏）")
	}
}
