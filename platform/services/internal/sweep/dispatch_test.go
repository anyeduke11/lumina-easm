package sweep

import (
	"context"
	"errors"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 为什么（ENH-01）：Temporal 模式下 sweep 行由 server 创建（同步返回 running），
// worker 按既有 ID 续执行并写穿进度——ExecuteInto 是 worker 侧唯一入口；
// 若允许 worker 重建行，断点语义（steps/findings 续加）就丢了。
func TestExecuteIntoResumesExistingRow(t *testing.T) {
	st := NewMemStore()
	s1, l1, as := setup()
	s1.SetStore(st)
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	// server 侧：建行+派发（本测试模拟 worker 接手）
	sw, err := s1.CreateDispatched(context.Background(), "t-a", []string{"P1"})
	if err != nil {
		t.Fatal(err)
	}
	if sw.Status != StatusRunning {
		t.Fatalf("CreateDispatched 应返回 running 行: %+v", sw)
	}
	s2, _, as2 := setup()
	s2.SetStore(st)
	s2.led = l1
	as2.m["t-a"] = as.m["t-a"]
	// worker 侧：按 ID 续跑
	done, err := s2.ExecuteInto(context.Background(), admin(), "w1", sw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusDone || done.Findings == 0 || len(done.Steps) != 4 {
		t.Fatalf("ExecuteInto 未按行续跑: %+v", done)
	}
	got, ok := s2.Get(sw.ID)
	if !ok || got.Status != StatusDone || got.Findings != done.Findings {
		t.Fatalf("持久行未同步: %+v ok=%v", got, ok)
	}
	// 未知/快照行拒绝执行（fail loud，防把 COV-* 当任务跑）
	if _, err := s2.ExecuteInto(context.Background(), admin(), "w2", "COV-t-a"); err == nil {
		t.Error("COV 行不得作为 sweep 执行")
	}
	if _, err := s2.ExecuteInto(context.Background(), admin(), "w3", "S-nope"); err == nil {
		t.Error("不存在的行应报错")
	}
}

// 为什么（NFR-AVL-003 断点续跑）：worker 崩溃后 Temporal 重试同一行——
// 已完成阶段必须跳过（steps 不翻倍、findings 不虚计），只补跑缺口阶段。
func TestExecuteIntoSkipsCompletedPhases(t *testing.T) {
	st := NewMemStore()
	s1, l1, as := setup()
	s1.SetStore(st)
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	sw, err := s1.CreateDispatched(context.Background(), "t-a", []string{"P1", "P2"})
	if err != nil {
		t.Fatal(err)
	}
	// 模拟崩溃前进度：P1 四步已写入行
	cur, _, _ := st.Get(context.Background(), sw.ID)
	for _, n := range []string{"基础域名归集", "公开附件排查", "风险页面核查", "页面内容核查"} {
		cur.Steps = append(cur.Steps, StepRun{Phase: "P1", Step: n, Status: "done", NewIssues: 1})
	}
	cur.Findings = 4
	if err := st.Save(context.Background(), &cur); err != nil {
		t.Fatal(err)
	}
	s2, _, as2 := setup()
	s2.SetStore(st)
	s2.led = l1
	as2.m["t-a"] = as.m["t-a"]
	done, err := s2.ExecuteInto(context.Background(), admin(), "w", sw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusDone {
		t.Fatalf("应完成: %+v", done)
	}
	p1steps, p2steps := 0, 0
	for _, sp := range done.Steps {
		switch sp.Phase {
		case "P1":
			p1steps++
		case "P2":
			p2steps++
		}
	}
	if p1steps != 4 || p2steps != 4 { // P1 不重跑（仍 4 步），P2 补齐（4 步）
		t.Errorf("断点续跑失败：P1=%d(应4) P2=%d(应4) steps=%+v", p1steps, p2steps, done.Steps)
	}
}

// 为什么（批六端到端实测缺陷 BUG-04）：worker 重启后 itemSeq 归零曾撞 ledger 主键
// （duplicate id 致整次活动失败）。回归口径：跨重启的新入账必须续接既有行号且不冲突。
func TestRestartLedgerIdContinuation(t *testing.T) {
	st := NewMemStore()
	s1, l1, as := setup()
	s1.SetStore(st)
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	if _, err := s1.Execute(context.Background(), admin(), "r1", "t-a", []string{"P1"}); err != nil {
		t.Fatal(err)
	}
	// 「重启」：先接回共享台账（真实装配顺序：NewService 带 ledger → SetStore hydrate），再入新资产
	s2, _, as2 := setup()
	s2.led = l1
	s2.SetStore(st) // 从 l1 既有行 hydrate itemSeq（旧实现此处仍为 0）
	na := riskyAsset()
	na.ID, na.Name, na.IP = "a2", "dbbackup.hddata.cn", "192.168.9.9"
	as2.m["t-a"] = append(as.m["t-a"], na)
	sw2, err := s2.Execute(context.Background(), admin(), "r2", "t-a", []string{"P1"})
	if err != nil {
		t.Fatalf("旧实现在此报 ledger: duplicate id: %v", err)
	}
	if sw2.Findings == 0 {
		t.Error("新资产应产生新入账（续接行号不得吞掉写入）")
	}
}

// 为什么（StepHook 崩溃注入 = ENH-01 演练的注入点本身）：注入失败必须
// ① 保留已完成 steps（断点存在）② 行状态 failed 可被续跑转正——否则演练无效。
func TestStepHookCrashPreservesBreakpoint(t *testing.T) {
	st := NewMemStore()
	s1, l1, as := setup()
	s1.SetStore(st)
	as.m["t-a"] = []asset.Asset{riskyAsset()}
	hookFired := 0
	s1.StepHook = func(sw *Sweep) error {
		hookFired++
		if len(sw.Steps) == 4 { // P1 四步落盘后崩：断点=完整阶段（阶段粒度语义）
			return errors.New("injected")
		}
		return nil
	}
	_, err := s1.Execute(context.Background(), admin(), "r1", "t-a", []string{"P1", "P2"})
	if err == nil || hookFired != 4 {
		t.Fatalf("注入未生效: %v %d", err, hookFired)
	}
	c, _, _ := st.Get(context.Background(), func() string {
		for _, sw := range s1.List("t-a") {
			return sw.ID
		}
		return ""
	}())
	if c.Status != StatusFailed || len(c.Steps) != 4 {
		t.Fatalf("崩溃后断点未保留: status=%s steps=%d", c.Status, len(c.Steps))
	}
	// 续跑转正（模拟 attempt2）：P1 跳过、P2 补齐 4 步
	s2, _, as2 := setup()
	s2.led = l1
	s2.SetStore(st)
	as2.m["t-a"] = as.m["t-a"]
	done, err := s2.ExecuteInto(context.Background(), admin(), "r2", c.ID)
	if err != nil || done.Status != StatusDone || len(done.Steps) != 8 {
		t.Fatalf("续跑失败: %v steps=%d status=%s", err, len(done.Steps), done.Status)
	}
	p1 := 0
	for _, sp := range done.Steps {
		if sp.Phase == "P1" {
			p1++
		}
	}
	if p1 != 4 {
		t.Error("续跑重跑了 P1（steps 应保留不翻倍）")
	}
}
