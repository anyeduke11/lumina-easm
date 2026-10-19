package sweep

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 为什么（ENH-01 前置 / NFR-AVL-003）：Temporal 接管后「断点续跑」与进度查询的事实源
// 必须是持久化 sweep 行（进程重启后仍能查到 status+steps+覆盖度）；
// 内存 Store 与 PG Store 同契约（C-6）——本组用例即两端共同验收。

func TestStoreContractMem(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	sw := &Sweep{ID: "S-1", Tenant: "t-a", Phases: []string{"P1"}, Status: StatusRunning,
		Steps: []StepRun{{Phase: "P1", Step: "基础域名归集", Status: "done", NewIssues: 2}}, Findings: 2}
	if err := st.Save(ctx, sw); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.Get(ctx, "S-1")
	if !ok || err != nil || got.Status != StatusRunning || got.Findings != 2 || len(got.Steps) != 1 {
		t.Fatalf("回读不完整: %+v %v %v", got, ok, err)
	}
	got.Status = StatusDone
	end := time.Now().UTC()
	got.EndedAt = &end
	if err := st.Save(ctx, &got); err != nil { // upsert（断点进度追加）
		t.Fatal(err)
	}
	again, _, _ := st.Get(ctx, "S-1")
	if again.Status != StatusDone || again.EndedAt == nil {
		t.Error("Save 非 upsert 或 ended_at 丢失")
	}
	list, _ := st.List(ctx, "t-a")
	if len(list) != 1 || list[0].ID != "S-1" {
		t.Errorf("List 错误: %+v", list)
	}
	if _, ok, _ := st.Get(ctx, "nope"); ok {
		t.Error("未知 ID 应 false")
	}
}

// 重启销账主断言：Store 注入后，sweep 与覆盖度跨 Service 重建不丢（矩阵不塌）。
// 这是 ENH-01「断点续跑」的事实源前提：Temporal worker 崩溃重启后按行续，不靠内存。
func TestSweepsAndCoveragePersistAcrossRebuild(t *testing.T) {
	st := NewMemStore()
	s1, l1, as := setup()
	s1.SetStore(st)
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	sw, err := s1.Execute(context.Background(), admin(), "r1", "t-a", []string{"P1"})
	if err != nil {
		t.Fatal(err)
	}
	if sw.Status != StatusDone || sw.Findings == 0 {
		t.Fatalf("首轮应完成且有发现: %+v", sw)
	}
	s2, _, as2 := setup() // 「重启」：新 Service + 同 Store + 同资产后端（资产库跨重启存续的语义）
	s2.SetStore(st)
	s2.led = l1 // 台账=去重事实源，必须跨重启共享（否则「重启」被模拟成了「换库」）
	as2.m["t-a"] = as.m["t-a"]
	got, ok := s2.Get(sw.ID)
	if !ok || got.Status != StatusDone || got.Findings != sw.Findings || len(got.Steps) != len(sw.Steps) {
		t.Fatalf("重启后 sweep 行不完整: %+v ok=%v", got, ok)
	}
	if cov, err := s2.Coverage("t-a", "P1"); err != nil || cov < 1 {
		t.Errorf("重启后覆盖度应续存，实际 %v %v", cov, err)
	}
	// 重放同阶段：去重（台账事实源）仍成立，findings 增量 0
	sw2, err := s2.Execute(context.Background(), admin(), "r2", "t-a", []string{"P1"})
	if err != nil {
		t.Fatal(err)
	}
	if sw2.Findings != 0 {
		t.Errorf("跨重建重放不得复制发现，实际 %d", sw2.Findings)
	}
}
