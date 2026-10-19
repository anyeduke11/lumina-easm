package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

// 为什么（011=五态跟踪的持久载体）：跟催/下架证据必须跨进程恢复——server 重启后
// 「已通报平台」的单还得继续跟到「已下架」，状态机与留痕一条不能丢。
// 双连接=跨进程视角；status 列与 JSONB 内状态必须同步（筛选面与内容面不一致=催办台漏单）。
func TestWorkOrderStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-wo"
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM work_orders WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)

	w := workorder.WorkOrder{
		ID: "WO-itest-1", Tenant: tid, LedgerID: "L-1", Channel: "repo.github",
		Target: "https://github.com/x/y/blob/main/backup.sql", Kind: "删除申请",
		Platform: "GitHub", Title: "泄露备份库文件", Owner: "安全运营",
		Status:    workorder.StatusPending,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		History: []workorder.Transition{{TS: time.Now().UTC(), To: workorder.StatusPending, Operator: "u1", Note: "建单"}},
	}
	if err := db.WorkOrders().Create(ctx, w); err != nil {
		t.Fatal(err)
	}
	// 重复建单 → ErrDuplicate（契约映射在 store 层同样成立）
	if err := db.WorkOrders().Create(ctx, w); err != workorder.ErrDuplicate {
		t.Errorf("重复建单应 ErrDuplicate: %v", err)
	}

	// 转移落库 + 独立连接读回（跨进程视角）
	w.Status = workorder.StatusReported
	w.History = append(w.History, workorder.Transition{TS: time.Now().UTC(), From: workorder.StatusPending, To: workorder.StatusReported, Operator: "u2"})
	w.UpdatedAt = time.Now().UTC()
	if err := db.WorkOrders().Update(ctx, w); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	got, err := db2.WorkOrders().Get(ctx, tid, "WO-itest-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != workorder.StatusReported || len(got.History) != 2 || got.Target != w.Target {
		t.Errorf("跨连接回读失真: %+v", got)
	}
	// status 列与 JSONB 内容同步（筛「已通报平台」必须命中）
	list, err := db2.WorkOrders().List(ctx, tid, workorder.StatusReported)
	if err != nil || len(list) != 1 {
		t.Errorf("状态筛选错误: %v %d", err, len(list))
	}
	// 跨租户不可读、不可更新（行级闸）
	if _, err := db2.WorkOrders().Get(ctx, "itest-other", "WO-itest-1"); err != workorder.ErrNotFound {
		t.Errorf("跨租户应 ErrNotFound: %v", err)
	}
	w.Tenant = "itest-other"
	if err := db2.WorkOrders().Update(ctx, w); err != workorder.ErrNotFound {
		t.Errorf("跨租户更新应 ErrNotFound（不得改写他租户单）: %v", err)
	}
	// 更新不存在的单=ErrNotFound（防静默 no-op）
	if err := db2.WorkOrders().Update(ctx, workorder.WorkOrder{ID: "WO-ghost", Tenant: tid}); err != workorder.ErrNotFound {
		t.Errorf("幽灵更新应 ErrNotFound: %v", err)
	}
}
