package pgstore

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
)

// 为什么（ENH-01）：server 与 Temporal worker 是两个进程，断点续跑/进度查询的
// 事实源必须落 PG 且与 MemStore 同契约（C-6）——本用例即 PG 端契约验收（无 DSN 跳过）。
func TestSweepStoreContractPG(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	st := db.Sweeps()
	ctx := context.Background()
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM sweeps WHERE id LIKE 'S-ITEST%' OR id LIKE 'COV-itest%'`) }
	cleanup()
	t.Cleanup(cleanup)

	sw := &sweep.Sweep{ID: "S-ITEST-1", Tenant: "itest-t", Phases: []string{"P1", "P2"}, Status: sweep.StatusRunning,
		Steps: []sweep.StepRun{{Phase: "P1", Step: "基础域名归集", Status: "done", Outputs: []string{"清单"}, NewIssues: 3}}}
	if err := st.Save(ctx, sw); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.Get(ctx, "S-ITEST-1")
	if !ok || err != nil {
		t.Fatalf("回读失败 %v %v", ok, err)
	}
	if got.Findings != 0 && got.Steps[0].NewIssues != 3 {
		t.Errorf("steps JSONB 反序列化不完整: %+v", got.Steps)
	}
	if got.Steps[0].Outputs[0] != "清单" || got.Phases[1] != "P2" {
		t.Errorf("数组字段丢失: %+v", got)
	}
	// upsert：断点进度追加 + ended_at
	got.Status = sweep.StatusDone
	got.Steps = append(got.Steps, sweep.StepRun{Phase: "P2", Step: "全域资产搜集", Status: "done"})
	end := sw.StartedAt
	got.EndedAt = &end
	if err := st.Save(ctx, &got); err != nil {
		t.Fatal(err)
	}
	again, _, _ := st.Get(ctx, "S-ITEST-1")
	if again.Status != sweep.StatusDone || len(again.Steps) != 2 || again.EndedAt == nil {
		t.Errorf("upsert/ended_at 失效: %+v", again)
	}
	// 覆盖度快照行可存可读（与内存契约同形）
	cov := &sweep.Sweep{ID: "COV-itest-t", Tenant: "itest-t", Status: "snapshot",
		Steps: []sweep.StepRun{{Phase: "P1", NewIssues: 7}}}
	if err := st.Save(ctx, cov); err != nil {
		t.Fatal(err)
	}
	c2, ok, _ := st.Get(ctx, "COV-itest-t")
	if !ok || c2.Steps[0].NewIssues != 7 {
		t.Error("COV 行契约破坏")
	}
	list, _ := st.List(ctx, "itest-t")
	if len(list) != 2 {
		t.Errorf("List 应含 sweep+COV 共 2 行，实际 %d", len(list))
	}
}
