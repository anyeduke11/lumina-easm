package pgstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（V-5 回归守卫）：ledger PG 实现是显式列（非 JSONB）——Item 新增字段若不同步
// 加列即被静默丢弃。实测缺陷：xchk 未加列时「双信源严重级」在 PG 模式仍被门1 降级
// （内存模式正常=双后端行为漂移）。本测试锁定 xchk 的建/读/状态迁移全链路持久化。
func TestLedgerStoreXChkRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-led"
	cleanup := func() {
		_, _ = db.sql.Exec(`DELETE FROM ledger_items WHERE tenant_id=$1`, tid)
		_, _ = db.sql.Exec(`DELETE FROM tenants WHERE id=$1`, tid)
	}
	cleanup()
	t.Cleanup(cleanup)
	ensureTenant(t, db, ctx, tid)

	base := func(id string, xchk []string) ledger.Item {
		return ledger.Item{
			ID: id, Tenant: tid, Phase: "P3", Category: "代码密码类", Asset: "a.itest.cn",
			Title: "私钥泄露", Level: "严重", Source: "P4/gitleaks",
			Found: time.Now().UTC(), Action: "删除", Owner: "运维部",
			Due: time.Now().UTC().Add(24 * time.Hour), Status: ledger.StatusOpen,
			XChk: xchk,
		}
	}
	it := base("L-itest-x1", []string{"rule:R-PRIVKEY", "tool:gitleaks"})
	if err := db.Ledgers().Create(ctx, it); err != nil {
		t.Fatal(err)
	}
	// 独立连接读回（跨进程视角）
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	got, err := db2.Ledgers().Get(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.XChk) != 2 || got.XChk[0] != "rule:R-PRIVKEY" || got.XChk[1] != "tool:gitleaks" {
		t.Errorf("xchk 应完整往返（门1 判据不得丢）: %v", got.XChk)
	}
	// 状态迁移必须保留 xchk（Update 整行回写，漏列=抹掉交叉信源）
	got.Status = ledger.StatusDoing
	if err := db2.Ledgers().Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, err := db2.Ledgers().Get(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Status != ledger.StatusDoing || len(got2.XChk) != 2 {
		t.Errorf("状态迁移后 xchk 应保留: st=%s xchk=%v", got2.Status, got2.XChk)
	}
	// 空 xchk 条目不得读成 nil 异常（默认 '{}' 列）
	empty := base("L-itest-x2", nil)
	if err := db.Ledgers().Create(ctx, empty); err != nil {
		t.Fatal(err)
	}
	ge, err := db2.Ledgers().Get(ctx, empty.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ge.XChk) != 0 {
		t.Errorf("空 xchk 应为空: %v", ge.XChk)
	}
}

// 为什么（V-10 回归守卫）：与 xchk（015）同类的「显式列丢字段」风险——refute 未加列时
// 门2 判据在 PG 模式静默丢失（内存正常=双后端漂移）。锁定反证记录的建/读/状态迁移持久化。
func TestLedgerStoreRefuteRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-led"
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM ledger_items WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)
	ensureTenant(t, db, ctx, tid)

	it := ledger.Item{
		ID: "L-itest-r1", Tenant: tid, Phase: "P3", Category: "代码密码类", Asset: "a.itest.cn",
		Title: "私钥泄露", Level: "严重", Source: "P4/gitleaks",
		Found: time.Now().UTC(), Action: "删除", Owner: "运维部",
		Due: time.Now().UTC().Add(24 * time.Hour), Status: ledger.StatusOpen,
		XChk: []string{"rule:R-KEY", "tool:gitleaks"},
		Refute: []ledger.RefuteCheck{
			{Claim: "命中位于示例/测试/夹具文件", Outcome: "excluded", Evidence: "file=src/main.go"},
		},
	}
	if err := db.Ledgers().Create(ctx, it); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	got, err := db2.Ledgers().Get(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refute) != 1 || got.Refute[0].Outcome != "excluded" || got.Refute[0].Evidence != "file=src/main.go" {
		t.Errorf("refute 应完整往返（门2 判据不得丢）: %+v", got.Refute)
	}
	// 状态迁移保留 refute（Update 整行回写）
	got.Status = ledger.StatusDoing
	if err := db2.Ledgers().Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, err := db2.Ledgers().Get(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2.Refute) != 1 || got2.XChk == nil {
		t.Errorf("状态迁移后 refute/xchk 应保留: refute=%+v xchk=%v", got2.Refute, got2.XChk)
	}
	// 空 refute 条目不得读异常（DDL 默认 '[]'）
	empty := ledger.Item{
		ID: "L-itest-r2", Tenant: tid, Phase: "P3", Category: "代码密码类", Asset: "b.itest.cn",
		Title: "备份可下载", Level: "高", Source: "P3/Dirsearch",
		Found: time.Now().UTC(), Action: "访问控制", Owner: "运维部",
		Due: time.Now().UTC().Add(24 * time.Hour), Status: ledger.StatusOpen,
	}
	if err := db.Ledgers().Create(ctx, empty); err != nil {
		t.Fatal(err)
	}
	ge, err := db2.Ledgers().Get(ctx, empty.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ge.Refute) != 0 {
		t.Errorf("空 refute 应为空: %+v", ge.Refute)
	}
}

// 为什么（S-2 回归守卫）：verifs 是门3 的持久载体——「已闭环」必须能回溯到
// 「谁、用什么方法、凭什么证据」验证过。与 xchk/refute 同类：显式列漏同步即静默丢失。
func TestLedgerStoreVerifsRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-led"
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM ledger_items WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)
	ensureTenant(t, db, ctx, tid)

	it := ledger.Item{
		ID: "L-itest-v1", Tenant: tid, Phase: "P3", Category: "代码密码类", Asset: "a.itest.cn",
		Title: "私钥泄露", Level: "高", Source: "P4/gitleaks",
		Found: time.Now().UTC(), Action: "删除", Owner: "运维部",
		Due: time.Now().UTC().Add(24 * time.Hour), Status: ledger.StatusOpen,
	}
	if err := db.Ledgers().Create(ctx, it); err != nil {
		t.Fatal(err)
	}
	// 验证记录追加（Verify 的持久面）
	it.Status = ledger.StatusClosed
	it.Verifs = []ledger.Verification{{
		Method: ledger.MethodManual, Result: ledger.ResultReproduced,
		Verifier: "u7", EvidenceRef: "minio://easm-evidence/verify/x.json",
		TS: time.Now().UTC(), Note: "人工复测通过",
	}}
	if err := db.Ledgers().Update(ctx, it); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	got, err := db2.Ledgers().Get(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Verifs) != 1 || got.Verifs[0].Method != ledger.MethodManual ||
		got.Verifs[0].EvidenceRef != "minio://easm-evidence/verify/x.json" || got.Verifs[0].Verifier != "u7" {
		t.Errorf("verifs 应完整往返（闭环依据不得丢）: %+v", got.Verifs)
	}
	if got.Status != ledger.StatusClosed {
		t.Errorf("状态应同步: %s", got.Status)
	}
}

// ensureTenant 保证测试租户存在（幂等）：三个台账集成测试共用 itest-led，
// 各自 cleanup 只清 ledger_items——若每个测试都无条件建租户，后跑的测试会撞主键
// （duplicate id）。租户行由 XChk 测试的 cleanup（含 tenants）负责清。
func ensureTenant(t *testing.T, db *DB, ctx context.Context, tid string) {
	t.Helper()
	if err := db.Tenants().Create(ctx, tenant.Tenant{ID: tid, Name: "集成台账客户", Short: "账", Status: "active"}); err != nil {
		if !errors.Is(err, tenant.ErrDuplicate) {
			t.Fatal(err)
		}
	}
}
