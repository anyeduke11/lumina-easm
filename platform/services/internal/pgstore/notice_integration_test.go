package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
)

// 为什么（012=CR-002 的持久载体）：通报是对外承诺动作——单号、目标、材料哈希、时间戳
// 必须跨进程（server 重启/worker）可查且**不可改写**；回执只追加。
// 本测试用双连接=跨进程视角，并直接验证「提交被篡改的 Notice 也改不动权威列」（结构性锁定）。
func TestNoticeStoreRoundTripAndLock(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-notice"
	created := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM notices WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)

	n := notice.Notice{
		ID: "NB-itest-1", Tenant: tid, LedgerID: "L-1", Target: notice.TargetPolice,
		DeadlineH: 24, Status: notice.StatusPending, Material: "# 线索通报\n- 条目：备份库泄露",
		MaterialHash: "aaa111", MaterialRef: "notice://" + tid + "/NB-itest-1", CreatedAt: created,
	}
	if err := db.Notices().Create(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := db.Notices().Create(ctx, n); err != notice.ErrDuplicate {
		t.Errorf("重复通报应 ErrDuplicate: %v", err)
	}

	db2, err := Open(dsn) // 第二连接=跨进程/重启视角
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()

	got, err := db2.Notices().Get(ctx, tid, "NB-itest-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != notice.TargetPolice || got.MaterialHash != "aaa111" || !got.CreatedAt.Equal(created) ||
		got.MaterialRef != n.MaterialRef || got.Material == "" {
		t.Errorf("跨连接回读失真: %+v", got)
	}

	// 抗篡改：客户端提交被改写的三要素（换目标/换哈希/换 ref/换时间戳/换单号）→ 权威列不动
	tamper := got
	tamper.Target = notice.TargetCenter
	tamper.MaterialHash = "EVIL-HASH"
	tamper.MaterialRef = "notice://x/evil"
	tamper.CreatedAt = created.Add(72 * time.Hour)
	if err := db2.Notices().Update(ctx, tamper); err != nil {
		t.Fatal(err)
	}
	after, err := db2.Notices().Get(ctx, tid, "NB-itest-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Target != notice.TargetPolice || after.MaterialHash != "aaa111" ||
		after.MaterialRef != n.MaterialRef || !after.CreatedAt.Equal(created) {
		t.Errorf("CR-002 三要素被篡改（列锁定失效）: %+v", after)
	}
	if after.ID != "NB-itest-1" || after.Tenant != tid {
		t.Errorf("单号/租户被改写: %+v", after)
	}

	// 回执=合法可变面（状态/回执号/报送时间落库）
	sub := time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)
	after.Status, after.ReceiptNo, after.SubmittedAt = notice.StatusSubmitted, "公网文〔2026〕9号", &sub
	if err := db2.Notices().Update(ctx, after); err != nil {
		t.Fatal(err)
	}
	fin, err := db2.Notices().Get(ctx, tid, "NB-itest-1")
	if err != nil || fin.Status != notice.StatusSubmitted || fin.ReceiptNo != "公网文〔2026〕9号" ||
		fin.SubmittedAt == nil || !fin.SubmittedAt.Equal(sub) {
		t.Errorf("回执未落库: %v %+v", err, fin)
	}

	// 跨租户读写全拒 + 状态筛选
	if _, err := db2.Notices().Get(ctx, "itest-other", "NB-itest-1"); err != notice.ErrNotFound {
		t.Errorf("跨租户读应 ErrNotFound: %v", err)
	}
	bad := fin
	bad.Tenant = "itest-other"
	if err := db2.Notices().Update(ctx, bad); err != notice.ErrNotFound {
		t.Errorf("跨租户更新应 ErrNotFound: %v", err)
	}
	list, err := db2.Notices().List(ctx, tid, notice.StatusSubmitted)
	if err != nil || len(list) != 1 {
		t.Errorf("已报送筛选错误: %v %v", err, list)
	}
	if l, _ := db2.Notices().List(ctx, tid, notice.StatusPending); len(l) != 0 {
		t.Errorf("状态迁移后待报送筛应空: %+v", l)
	}

	// DB CHECK 约束：非法目标名不可入库（守卫在库层，不只应用层）
	if err := db2.Notices().Create(ctx, notice.Notice{ID: "NB-bad-target", Tenant: tid, LedgerID: "L-1",
		Target: "某个媒体", Status: notice.StatusPending, MaterialHash: "h",
		MaterialRef: "r", CreatedAt: created}); err == nil {
		_, _ = db2.sql.Exec(`DELETE FROM notices WHERE id='NB-bad-target'`)
		t.Error("非法通报目标应被 DB CHECK 拒绝")
	}
}
