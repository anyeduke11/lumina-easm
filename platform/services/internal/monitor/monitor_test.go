package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

func visible() map[string][]asset.Asset {
	return map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "cache.hddata.cn", Tags: []string{"redis"}},
		{ID: "a2", Tenant: "t-a", Name: "graf.hddata.cn", Tags: []string{"grafana"}},
		{ID: "a3", Tenant: "t-a", Name: "phish-bank.top", Tags: []string{}}, // seed IOC conf=0.9 应命中
	}}
}

func newSvc(v *map[string][]asset.Asset) *Service {
	return New(vuln.NewService(), intel.NewService(), func() map[string][]asset.Asset { return *v })
}

// 为什么（FR-MON-004）：告警收敛=只推高危。medium 漏洞（grafana,6.5→公式<80 但 severity=medium）
// 与低置信 IOC 若进告警流，会把复核噪声推给监管出口（PRD「只推高危」违例）。
func TestScanHighRiskOnly(t *testing.T) {
	s := newSvc(nil) // provider nil：仅用显式 scanAt
	s.Add("m", "both", time.Hour)
	alerts := s.scanAt("test", 1, "", visible())
	if alerts == 0 {
		t.Fatal("redis critical 匹配与 c2 域命中应产生告警")
	}
	hits := map[string]bool{}
	for _, a := range s.List("") {
		hits[a.Key] = true
		if a.Severity == "medium" {
			t.Errorf("medium 漏洞不得进告警流: %+v", a)
		}
		if strings.Contains(a.Ref, "fake-recruit") {
			t.Errorf("confidence 0.7 < 0.8 的 IOC 不得推送: %+v", a)
		}
	}
	if !hits["vuln_match|CVE-2026-20201|a1"] {
		t.Error("redis critical 未命中 a1")
	}
}

// 为什么（FR-MON-004 验收「告警去重，无重复推送」）：同 (kind,ref,asset) 重扫不得复制告警。
// 去重集是幂等守卫点——变异（强制跳过查重）必须被本用例捕获。
func TestDedupNoRepeat(t *testing.T) {
	v := visible()
	s := newSvc(&v)
	s.Add("m", "both", time.Hour)
	n1, _ := s.RunNow(1)
	before := len(s.List(""))
	n2, _ := s.RunNow(1)
	if n2 != 0 {
		t.Errorf("重扫 new 应为 0（去重），实际 %d", n2)
	}
	if len(s.List("")) != before {
		t.Error("告警条目被重复推送")
	}
	if n1 <= 0 || before != n1 {
		t.Errorf("首轮应产生 %d 条，实际 %d", n1, before)
	}
}

// 只推高危 + 按置信度排序（FR-MON-004）；置信度须单调不增。
func TestSortByConfidence(t *testing.T) {
	v := visible()
	s := newSvc(&v)
	s.Add("m", "both", time.Hour)
	s.RunNow(1)
	list := s.List("")
	if len(list) < 2 {
		t.Fatal("样本不足")
	}
	for i := 1; i < len(list); i++ {
		if list[i].Confidence > list[i-1].Confidence {
			t.Fatalf("未按置信度降序: %+v", list)
		}
	}
}

// 为什么（FR-MON-001 验收「任务按配置周期执行，可查询历史」）：定时 tick 必须真实触发扫描并留痕。
func TestScheduledTickAndHistory(t *testing.T) {
	v := visible()
	s := newSvc(&v)
	spec, err := s.Add("每30ms", "both", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for len(s.History(spec.ID)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(s.History(spec.ID)) == 0 {
		t.Fatal("调度未按时执行（FR-MON-001 违例）")
	}
	r := s.History(spec.ID)[0]
	if r.Trigger != "cron" {
		t.Errorf("定时触发标记错误: %+v", r)
	}
	cancel() // 停表后不再增长
	time.Sleep(150 * time.Millisecond)
	stopped := len(s.History(spec.ID))
	time.Sleep(150 * time.Millisecond)
	if len(s.History(spec.ID)) != stopped {
		t.Error("取消 ctx 后调度未停止")
	}
}

// 事件驱动（FR-MON-001/003 近似）：新 CVE/IOC 导入即触发匹配扫描，无需等待周期。
func TestOnImportEvent(t *testing.T) {
	v := visible()
	s := newSvc(&v)
	before := len(s.List(""))
	n := s.OnImport("vuln", v)
	if before != 0 || n <= 0 {
		t.Fatalf("导入事件应立即产出告警: before=%d n=%d", before, n)
	}
	if s.OnImport("vuln", v) != 0 {
		t.Error("同输入事件重放不得复制告警")
	}
}

func TestInvalidKind(t *testing.T) {
	s := newSvc(nil)
	if _, err := s.Add("bad", "wifi", time.Hour); err == nil {
		t.Error("kind 非 vuln|intel|both 必须报错（fail loud）")
	}
	if _, err := s.Get(999); err == nil {
		t.Error("不存在的监控器必须报错")
	}
}
