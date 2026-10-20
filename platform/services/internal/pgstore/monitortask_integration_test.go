package pgstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// 为什么（M4-03 / 021）：排查任务单=触发链的合规记录，双后端必须同契约——
// 同源 pending 单收敛刷新（不开新行）、done 终态可再触发、跨进程可查。与内存实现同用例对账（C-6）。
func TestMonitorTaskStoreRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Open(kbDSN(t)) // 第二「进程」
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, st2 := db.MonitorTasks(), db2.MonitorTasks()
	t.Cleanup(func() {
		_, _ = db.sql.Exec(`DELETE FROM monitor_tasks WHERE tenant_id LIKE 'itest%'`)
	})
	_, _ = db.sql.Exec(`DELETE FROM monitor_tasks WHERE tenant_id LIKE 'itest%'`)

	tk := monitor.Task{
		ID: "RT-itest0001", Tenant: "itest-mon", AssetID: "a1", AssetName: "www",
		Trigger: monitor.TriggerDiffNew, Reason: "资产新增（diff）",
		Status: monitor.TaskPending, CreatedAt: time.Now().UTC(),
	}
	created, err := st.AddTask(ctx, tk)
	if err != nil || !created {
		t.Fatalf("首开单应 created: %v %v", created, err)
	}
	// 同源重放=收敛刷新（不开新行，跨连接幂等）
	tk2 := tk
	tk2.ID = "RT-itest0002"
	tk2.Reason = "资产新增（diff·刷新）"
	created2, _ := st2.AddTask(ctx, tk2)
	if created2 {
		t.Fatal("同源 pending 单重放应收敛刷新（created=false）")
	}
	ls, err := st2.ListTasks(ctx, "itest-mon", "")
	if err != nil || len(ls) != 1 || ls[0].ID != "RT-itest0001" || ls[0].Reason != "资产新增（diff·刷新）" {
		t.Fatalf("收敛刷新未跨进程生效: %+v %v", ls, err)
	}
	// 闭环：pending→done；重复 done=ErrTaskClosed；不存在=ErrTaskNotFound
	done, err := st.DoneTask(ctx, "itest-mon", "RT-itest0001", "u1", "已重扫无新增")
	if err != nil || done.Status != "done" || done.By != "u1" || done.DoneAt == nil {
		t.Fatalf("闭环元数据: %+v %v", done, err)
	}
	if _, err := st2.DoneTask(ctx, "itest-mon", "RT-itest0001", "u1", "再点"); !errors.Is(err, monitor.ErrTaskClosed) {
		t.Fatalf("重复闭环应 ErrTaskClosed: %v", err)
	}
	if _, err := st2.DoneTask(ctx, "itest-mon", "RT-nope", "u1", ""); !errors.Is(err, monitor.ErrTaskNotFound) {
		t.Fatalf("不存在应 ErrTaskNotFound: %v", err)
	}
	// 闭环后同源再触发=新行（新一轮事实）
	tk3 := tk
	tk3.ID = "RT-itest0003"
	created3, _ := st.AddTask(ctx, tk3)
	if !created3 {
		t.Fatal("闭环后同源应可再开单")
	}
	pend, _ := st.ListTasks(ctx, "itest-mon", "pending")
	done2, _ := st.ListTasks(ctx, "itest-mon", "done")
	if len(pend) != 1 || len(done2) != 1 {
		t.Fatalf("状态过滤/闭环计数: pending=%d done=%d", len(pend), len(done2))
	}
}
