package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 为什么（FR-MON-002 销账）：增量 Diff=「新增/变更/消失」三类输出，验收=Diff 与资产事实一致。
// 首跑只立基线不报 diff（否则首轮=全量误报「新增」，告警流被历史资产灌满——监管不可用）。

type memSnap struct{ m map[string]map[string]string }

func newMemSnap() *memSnap { return &memSnap{m: map[string]map[string]string{}} }
func (s *memSnap) LoadSnapshot(_ context.Context, tenant string) (map[string]string, error) {
	return s.m[tenant], nil
}
func (s *memSnap) SaveSnapshot(_ context.Context, tenant string, snap map[string]string) error {
	cp := map[string]string{}
	for k, v := range snap {
		cp[k] = v
	}
	s.m[tenant] = cp
	return nil
}

func v1() map[string][]asset.Asset {
	return map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "www.a.cn", Risk: "high", Exp: 60, Status: "在用", IP: "1.1.1.1"},
		{ID: "a2", Tenant: "t-a", Name: "api.a.cn", Risk: "medium", Exp: 30, Status: "在用"},
	}}
}

func TestDiffFirstRunBaseline(t *testing.T) {
	s := New(nil, nil, nil)
	st := newMemSnap()
	s.SetSnapStore(st)
	if n := s.DiffScan(context.Background(), v1()); n != 0 {
		t.Errorf("首跑应 0 告警（只立基线），实际 %d", n)
	}
	if len(st.m["t-a"]) != 2 {
		t.Errorf("基线应含 2 资产，实际 %d", len(st.m["t-a"]))
	}
	if n2 := s.DiffScan(context.Background(), v1()); n2 != 0 { // 无变化重扫
		t.Errorf("无变化重扫应 0，实际 %d", n2)
	}
}

func TestDiffAddedChangedRemoved(t *testing.T) {
	s := New(nil, nil, nil)
	s.SetSnapStore(newMemSnap())
	s.DiffScan(context.Background(), v1()) // 基线：a1,a2
	// 当前态：a1 暴露度 60→95（变更）、a3 新增（critical）、a2 消失
	cur2 := map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "www.a.cn", Risk: "high", Exp: 95, Status: "在用", IP: "1.1.1.1"},
		{ID: "a3", Tenant: "t-a", Name: "new.a.cn", Risk: "critical", Exp: 80, Status: "在用"},
	}}
	if n := s.DiffScan(context.Background(), cur2); n != 3 {
		t.Fatalf("应 3 条 diff（增1/改1/删1），实际 %d", n)
	}
	var added, changed, removed bool
	for _, al := range s.List("asset_diff") {
		switch {
		case strings.Contains(al.Msg, "新增"):
			added = true
			if al.Severity != "critical" {
				t.Errorf("新增告警等级应随资产 risk，实际 %s: %s", al.Severity, al.Msg)
			}
		case strings.Contains(al.Msg, "变更"):
			changed = true
		case strings.Contains(al.Msg, "消失"):
			removed = true
			if al.Severity != "medium" { // 消失≠高危（可能正常下线）：留告警流但不走出口（只推高危闸自然挡下）
				t.Errorf("消失类应 medium 不外发，实际 %s", al.Severity)
			}
		}
	}
	if !added || !changed || !removed {
		t.Fatalf("三类 diff 不全: added=%v changed=%v removed=%v", added, changed, removed)
	}
	if n2 := s.DiffScan(context.Background(), cur2); n2 != 0 { // 幂等：key 含指纹
		t.Errorf("重扫应 0，实际 %d", n2)
	}
	// a1 再次变更 → 新告警（指纹变化突破去重键）
	cur3 := map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "www.a.cn", Risk: "high", Exp: 100, Status: "在用", IP: "1.1.1.1"},
		{ID: "a3", Tenant: "t-a", Name: "new.a.cn", Risk: "critical", Exp: 80, Status: "在用"},
	}}
	if n3 := s.DiffScan(context.Background(), cur3); n3 != 1 {
		t.Errorf("a1 再变更应 1 条，实际 %d", n3)
	}
}

// failSnap 写快照总失败（LoadSnapshot 返回固定 prev），验证：若同指纹告警被重复扫出，
// keys 去重必须兜底（FR-MON-004 纵深防御——快照失败≠重复推送的许可）。
type failSnap struct{ prev map[string]string }

func (f *failSnap) LoadSnapshot(_ context.Context, _ string) (map[string]string, error) {
	return f.prev, nil
}
func (f *failSnap) SaveSnapshot(_ context.Context, _ string, _ map[string]string) error {
	return context.DeadlineExceeded // 模拟 DB 写失败
}

func TestDiffDedupWhenSnapshotSaveFails(t *testing.T) {
	s := New(nil, nil, nil)
	// 基线里 a1=Exp60，但当前 a1=Exp95 变更；Save 总失败→每次 Load 仍拿到 Exp60 基线
	s.SetSnapStore(&failSnap{prev: map[string]string{
		"a1": "www.a.cn\x1fhigh\x1f60\x1f在用\x1f1.1.1.1\x1f",
	}})
	cur := map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "www.a.cn", Risk: "high", Exp: 95, Status: "在用", IP: "1.1.1.1"},
	}}
	if n := s.DiffScan(context.Background(), cur); n != 1 {
		t.Fatalf("首扫变更应 1 条，实际 %d", n)
	}
	// 重扫：Load 仍返回旧基线→若未去重，会再产 1 条同指纹告警
	if n := s.DiffScan(context.Background(), cur); n != 0 {
		t.Errorf("去重兜底失败：重扫应 0，实际 %d", n)
	}
	if got := len(s.List("asset_diff")); got != 1 {
		t.Errorf("asset_diff 告警应恰好 1 条，实际 %d", got)
	}
}

// 为什么（kind=diff 走监控器全机制）：scanAt 的 diff 分支必须与定时/手动/历史接线一致——
// 监控器创建(kind=diff)→首扫立基线→变更扫出告警→history 留痕。
func TestScanAtDiffKind(t *testing.T) {
	s := New(nil, nil, nil) // diff 分支不触碰 vuln/intel 服务
	s.SetSnapStore(newMemSnap())
	sp, err := s.Add("资产增量监控", "diff", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.scanAt("manual", sp.ID, "", v1()); n != 0 {
		t.Fatalf("首扫应立基线 0 告警，实际 %d", n)
	}
	mutated := map[string][]asset.Asset{"t-a": {
		{ID: "a1", Tenant: "t-a", Name: "www.a.cn", Risk: "high", Exp: 99, Status: "在用", IP: "1.1.1.1"},
		{ID: "a2", Tenant: "t-a", Name: "api.a.cn", Risk: "medium", Exp: 30, Status: "在用"},
	}}
	if n := s.scanAt("manual", sp.ID, "", mutated); n != 1 {
		t.Fatalf("变更应扫出 1 条，实际 %d", n)
	}
	h := s.History(sp.ID)
	if len(h) != 2 || h[1].Trigger != "manual" || h[1].New != 1 {
		t.Errorf("diff 轮未留痕: %+v", h)
	}
}
