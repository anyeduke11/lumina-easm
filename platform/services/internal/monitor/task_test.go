package monitor

// FR-MON-003 销账：资产新增/变更/新 POC 发布 → 触发并生成**排查任务单**（可查询、可完成）。
// M1 批只做到「导入事件→告警」，任务单是本批新增面（M4-03）。

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

func taskSvc(t *testing.T) (*Service, *memSnap) {
	t.Helper()
	s := New(nil, nil, func() map[string][]asset.Asset { return nil })
	st := newMemSnap() // 复用 diff_test.go 夹具（内存快照）
	s.SetSnapStore(st)
	return s, st
}

func vis(tid string, as ...asset.Asset) map[string][]asset.Asset {
	return map[string][]asset.Asset{tid: as}
}

// 验收①：新资产 → diff_new 任务单（FR-MON-003）。
func TestDiffEnqueuesRescanTask(t *testing.T) {
	s, _ := taskSvc(t)
	// 首轮只立基线（不误报新增）
	if n := s.DiffScan(context.Background(), vis("t-a", asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high"})); n != 0 {
		t.Fatalf("首轮应只立基线: %d", n)
	}
	// 新资产入列 → 告警 + 任务单
	n := s.DiffScan(context.Background(), vis("t-a",
		asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high"},
		asset.Asset{ID: "a2", Tenant: "t-a", Name: "api", Risk: "high"}))
	if n != 1 {
		t.Fatalf("期望 1 条新增告警: %d", n)
	}
	ts, err := s.Tasks(context.Background(), "t-a", "")
	if err != nil || len(ts) != 1 {
		t.Fatalf("新资产应生成 1 张任务单: %+v %v", ts, err)
	}
	if ts[0].Trigger != TriggerDiffNew || ts[0].AssetID != "a2" || ts[0].Status != TaskPending {
		t.Fatalf("任务单元数据不符: %+v", ts[0])
	}
	if !hasPrefix(ts[0].ID, "RT-") {
		t.Fatalf("任务单 ID 前缀: %s", ts[0].ID)
	}
	// 同指纹重扫：幂等不重复开单
	_ = s.DiffScan(context.Background(), vis("t-a",
		asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high"},
		asset.Asset{ID: "a2", Tenant: "t-a", Name: "api", Risk: "high"}))
	ts2, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts2) != 1 {
		t.Fatalf("同状态重扫不得重复开单: %+v", ts2)
	}
}

// 验收②：资产变更（指纹变化）→ diff_changed 任务单。
func TestDiffChangedEnqueuesTask(t *testing.T) {
	s, _ := taskSvc(t)
	_ = s.DiffScan(context.Background(), vis("t-a", asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high", Exp: 40}))
	n := s.DiffScan(context.Background(), vis("t-a", asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high", Exp: 95}))
	if n != 1 {
		t.Fatalf("变更应有 1 条告警: %d", n)
	}
	ts, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts) != 1 || ts[0].Trigger != TriggerDiffChanged {
		t.Fatalf("变更应生成 diff_changed 任务单: %+v", ts)
	}
	// 再变一次（指纹再动）→ 收敛刷新同一张 pending 单（ID 不变、触发时间更新，不堆叠）
	before := ts[0]
	time.Sleep(2 * time.Millisecond)
	_ = s.DiffScan(context.Background(), vis("t-a", asset.Asset{ID: "a1", Tenant: "t-a", Name: "www", Risk: "high", Exp: 100}))
	ts2, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts2) != 1 || ts2[0].ID != before.ID || !ts2[0].CreatedAt.After(before.CreatedAt) {
		t.Fatalf("同源 pending 单应收敛刷新而非堆叠: %+v", ts2)
	}
}

// 验收③：新 POC/CVE 发布 → 受影响资产任务单（tenant 级=全租户重扫）。
func TestOnNewPOCEnqueuesTasks(t *testing.T) {
	s, _ := taskSvc(t)
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-2026-1234", []asset.Asset{
		{ID: "a1", Tenant: "t-a", Name: "www"},
		{ID: "a2", Tenant: "t-a", Name: "api"},
	})
	ts, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts) != 2 {
		t.Fatalf("POC 影响 2 资产应开 2 单: %+v", ts)
	}
	for _, tk := range ts {
		if tk.Trigger != TriggerNewPOC || !contains3(tk.Reason, "CVE-2026-1234") {
			t.Fatalf("POC 任务单元数据: %+v", tk)
		}
	}
	// 幂等：同 POC 重放不重复开单
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-2026-1234", []asset.Asset{
		{ID: "a1", Tenant: "t-a", Name: "www"},
		{ID: "a2", Tenant: "t-a", Name: "api"},
	})
	ts2, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts2) != 2 {
		t.Fatalf("同 POC 重放幂等: %+v", ts2)
	}
	// 受影响资产为空=tenant 级全量重扫单
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-2026-9999", nil)
	ts3, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts3) != 3 {
		t.Fatalf("空受影响集应开 tenant 级任务单: %+v", ts3)
	}
	foundTenantLevel := false
	for _, tk := range ts3 {
		if tk.AssetID == "*" && contains3(tk.Reason, "CVE-2026-9999") {
			foundTenantLevel = true
		}
	}
	if !foundTenantLevel {
		t.Fatalf("tenant 级任务单缺失: %+v", ts3)
	}
}

// 验收④：任务单可完成；完成后同键可再开单（新一轮触发=新事实）。
func TestTaskDoneAndReopen(t *testing.T) {
	s, _ := taskSvc(t)
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-1", []asset.Asset{{ID: "a1", Tenant: "t-a", Name: "www"}})
	ts, _ := s.Tasks(context.Background(), "t-a", "")
	id := ts[0].ID
	done, err := s.TaskDone(context.Background(), "t-a", id, "u1", "已重扫无新增")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != TaskDone || done.By != "u1" || done.Note != "已重扫无新增" || done.DoneAt == nil {
		t.Fatalf("完成态元数据: %+v", done)
	}
	// 重复 done=409 哨兵（终态不得反复虚报闭环）
	if _, err := s.TaskDone(context.Background(), "t-a", id, "u1", "再点一次"); err != ErrTaskClosed {
		t.Fatalf("已完成任务单重复 done 应 ErrTaskClosed: %v", err)
	}
	// 同键新触发 → 新单（前单已闭环）
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-1", []asset.Asset{{ID: "a1", Tenant: "t-a", Name: "www"}})
	ts2, _ := s.Tasks(context.Background(), "t-a", "")
	if len(ts2) != 2 {
		t.Fatalf("闭环后同键应可再开单: %+v", ts2)
	}
}

func TestTaskNotFoundAndFilter(t *testing.T) {
	s, _ := taskSvc(t)
	if _, err := s.TaskDone(context.Background(), "t-a", "RT-nope", "u1", ""); err != ErrTaskNotFound {
		t.Fatalf("不存在任务单应 ErrTaskNotFound: %v", err)
	}
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-1", []asset.Asset{{ID: "a1", Tenant: "t-a", Name: "www"}})
	_ = s.OnNewPOC(context.Background(), "t-a", "CVE-2", []asset.Asset{{ID: "a2", Tenant: "t-a", Name: "api"}})
	_, _ = s.TaskDone(context.Background(), "t-a", func() string { ts, _ := s.Tasks(context.Background(), "t-a", ""); return ts[0].ID }(), "u1", "")
	pend, _ := s.Tasks(context.Background(), "t-a", string(TaskPending))
	done, _ := s.Tasks(context.Background(), "t-a", string(TaskDone))
	if len(pend) != 1 || len(done) != 1 {
		t.Fatalf("状态过滤失效: pending=%d done=%d", len(pend), len(done))
	}
	// 租户隔离：t-b 无任务单
	other, _ := s.Tasks(context.Background(), "t-b", "")
	if len(other) != 0 {
		t.Fatalf("跨租户任务单应不可见: %+v", other)
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func contains3(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = time.Now
