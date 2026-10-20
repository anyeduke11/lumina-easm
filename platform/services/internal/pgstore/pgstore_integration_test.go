package pgstore

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 集成测试需本地 PG + 已应用 migrations/001、002。缺 DSN 自动跳过。
// DSN 必须是 easm_app 角色（RLS 生效），如：
//
//	export EASM_PG_DSN=postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable
func mustDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	// 清理上轮残留（DELETE 权限已由 002 授予 easm_app）
	cleanup := func(c *sql.DB) {
		_, _ = c.Exec(`DELETE FROM graph_edges WHERE tenant_id LIKE 'itest-%'`)
		_, _ = c.Exec(`DELETE FROM graph_nodes WHERE tenant_id LIKE 'itest-%'`)
		_, _ = c.Exec(`DELETE FROM audit_logs WHERE tenant_id LIKE 'itest-%' OR actor LIKE 'itest%'`)
		_, _ = c.Exec(`DELETE FROM assets WHERE tenant_id LIKE 'itest-%'`)
		_, _ = c.Exec(`DELETE FROM tenants WHERE id LIKE 'itest-%'`)
	}
	raw, err := sql.Open("postgres", dsn)
	if err == nil {
		cleanup(raw)
		raw.Close()
	}
	t.Cleanup(func() {
		c, err := sql.Open("postgres", dsn)
		if err == nil {
			cleanup(c)
			c.Close()
		}
	})
	return db
}

func seedTenant(t *testing.T, ts *TenantStore, id string) {
	t.Helper()
	if err := ts.Create(context.Background(), tenant.Tenant{ID: id, Name: id, Status: "active", RootDomains: []string{"hddata.cn"}}); err != nil {
		t.Fatal(err)
	}
}

func mkAsset(tenantID, id string) asset.Asset {
	return asset.Asset{
		ID: id, Tenant: tenantID, Name: id + ".cn", Type: "domain", TypeLabel: "域名",
		Risk: "high", Exp: 60, Owner: "运维部", Found: time.Now().UTC(),
		Status: "在用", Beian: "已备案", Source: "P2/Fofa", Biz: "门户",
		Tags: []string{"web", "nginx"}, Ports: []int{80, 443}, Tech: []string{"nginx/1.24"},
	}
}

func TestTenantStoreRoundTrip(t *testing.T) {
	db := mustDB(t)
	ts := db.Tenants()
	ctx := context.Background()
	seedTenant(t, ts, "itest-ta")

	if err := ts.Create(ctx, tenant.Tenant{ID: "itest-ta", Name: "dup"}); err != tenant.ErrDuplicate {
		t.Errorf("重复 ID 期望 ErrDuplicate，实际 %v", err)
	}
	got, err := ts.Get(ctx, "itest-ta")
	if err != nil || got.Name != "itest-ta" {
		t.Fatalf("Get 失败: %+v %v", got, err)
	}
	if len(got.RootDomains) != 1 || got.RootDomains[0] != "hddata.cn" {
		t.Errorf("数组字段往返错误: %v", got.RootDomains)
	}
}

// 为什么（FR-TEN-005 / 一票否决④）：RLS 是查询路径拼错时的最后防线。
// 即使 SQL 的 WHERE 被改坏，只要 GUC 设了 ta，就必须读不到 tb 的行。
func TestAssetRLSHidesOtherTenantEvenWithBogusWhere(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	as := db.Assets()
	seedTenant(t, db.Tenants(), "itest-ta")
	seedTenant(t, db.Tenants(), "itest-tb")

	if err := as.Create(ctx, mkAsset("itest-ta", "itest-a1")); err != nil {
		t.Fatal(err)
	}
	if err := as.Create(ctx, mkAsset("itest-tb", "itest-b1")); err != nil {
		t.Fatal(err)
	}
	list, err := as.ListByTenant(ctx, "itest-ta")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "itest-a1" {
		t.Fatalf("t-a 列表应只含 itest-a1，实际 %+v", list)
	}
	if list[0].Exp != 60 || len(list[0].Tags) != 2 || list[0].Ports[1] != 443 {
		t.Errorf("数组/数值字段往返错误: %+v", list[0])
	}

	// 直接裸 SQL：GUC=itest-ta 但 WHERE 故意写 id 精确命中 tb 的行 → 必须 0 行
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('easm.tenant_id', 'itest-ta', true)`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM assets WHERE id = 'itest-b1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("RLS 失效：GUC=itest-ta 竟能看到 itest-tb 的行 (n=%d)", n)
	}

	// WITH CHECK：GUC=ta 时插入 tenant_id=tb 必须被数据库拒绝
	_, err = tx.Exec(`INSERT INTO assets (id,tenant_id,name,type,risk,exp,owner,status,beian)
VALUES ('itest-x','itest-tb','x','domain','low',1,'o','在用','未备案')`)
	if err == nil {
		t.Fatal("跨租户插入必须被 RLS WITH CHECK 拒绝")
	}
	if !isRLSDeny(err) {
		t.Logf("拒绝错误形态: %v", err) // 42501 之外的拒绝形态也接受非 0 错误
	}
}

func TestAssetGetVisibleForServiceAuthz(t *testing.T) {
	db := mustDB(t)
	ctx := context.Background()
	as := db.Assets()
	seedTenant(t, db.Tenants(), "itest-ta")
	if err := as.Create(ctx, mkAsset("itest-ta", "itest-g1")); err != nil {
		t.Fatal(err)
	}
	// Get 不设 GUC（穿透模式）：Service 层负责 InScope 判权，故行必须可读
	got, err := as.Get(ctx, "itest-g1")
	if err != nil {
		t.Fatalf("平台穿透读应成功: %v", err)
	}
	if got.Tenant != "itest-ta" || got.Status != "在用" {
		t.Errorf("Get 字段错误: %+v", got)
	}
	if _, err := as.Get(ctx, "itest-missing"); err != asset.ErrNotFound {
		t.Errorf("不存在应 ErrNotFound，实际 %v", err)
	}
}
