package usage

// FR-HRN-10 / M4-07：模型调用成本统计与预算告警。
// 语义：AI 面每次调用（mm 判敏/shadow 文案/后续 ENH 消费面）按租户留痕（token 计量）→
// 月度汇总 → 预算（默认=env 或租户级设置；0=未设预算，如实标注不告警）→ 超预算当月一次
// 告警（告警出口经 notify 统一通道，去重由 notify_log 兜底）。

import (
	"context"
	"testing"
	"time"
)

func newSvc(t *testing.T) (*Service, *MemStore, *fakeSink) {
	t.Helper()
	st := NewMemStore()
	sink := &fakeSink{}
	return New(st).WithSink(sink.record), st, sink
}

// fakeSink 预算告警出口夹具（main 装配=notify 统一通道；测试断言告警恰好一次）。
type fakeSink struct {
	alerts []Alert
}

func (f *fakeSink) record(_ context.Context, a Alert) error {
	f.alerts = append(f.alerts, a)
	return nil
}

func rec(tenant, feature, model string, total int64) Event {
	now := time.Now().UTC()
	return Event{Tenant: tenant, Feature: feature, Model: model,
		PromptTokens: total / 2, CompletionTokens: total - total/2, TotalTokens: total, TS: now}
}

func TestRecordAndSummary(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	if _, err := svc.Record(ctx, rec("t-a", "mm", "m1", 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Record(ctx, rec("t-a", "shadow_ai", "m1", 50)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Record(ctx, rec("t-a", "mm", "m2", 30)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Record(ctx, rec("t-b", "mm", "m1", 999)); err != nil {
		t.Fatal(err)
	}
	sum, err := svc.Summary(ctx, "t-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Calls != 3 || sum.TotalTokens != 180 || sum.ByFeature["mm"] != 130 || sum.ByModel["m1"] != 150 {
		t.Fatalf("汇总不符: %+v", sum)
	}
	// 租户隔离
	sumB, _ := svc.Summary(ctx, "t-b", "")
	if sumB.TotalTokens != 999 {
		t.Fatalf("跨租户串数: %+v", sumB)
	}
}

func TestBudgetExceededAlertOncePerMonth(t *testing.T) {
	svc, st, sink := newSvc(t)
	ctx := context.Background()
	if err := svc.SetBudget(ctx, "t-a", 150, "u1"); err != nil {
		t.Fatal(err)
	}
	b, ok, err := svc.GetBudget(ctx, "t-a")
	if err != nil || !ok || b != 150 {
		t.Fatalf("预算读取: %d %v %v", b, ok, err)
	}
	// 100 未超；再 50 → 触线：当月一次告警
	if _, err := svc.Record(ctx, rec("t-a", "mm", "m1", 100)); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 0 {
		t.Fatalf("未触线不得告警: %+v", sink.alerts)
	}
	if _, err := svc.Record(ctx, rec("t-a", "mm", "m1", 50)); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 {
		t.Fatalf("触线应告警一次: %+v", sink.alerts)
	}
	if sink.alerts[0].TenantID != "t-a" || sink.alerts[0].Kind != "budget" {
		t.Fatalf("告警元数据: %+v", sink.alerts[0])
	}
	// 同月继续超=不再重复告警（出口去重兜底之外的第二闸）
	_, _ = svc.Record(ctx, rec("t-a", "mm", "m1", 500))
	if len(sink.alerts) != 1 {
		t.Fatalf("同月应只告警一次: %+v", sink.alerts)
	}
	// 已告警标记可查（当月不重复的判定面）
	marked, err := st.BudgetAlertMarked(ctx, "t-a", time.Now().UTC().Format("2006-01"))
	if err != nil || !marked {
		t.Fatalf("当月告警标记应置位: %v %v", marked, err)
	}
	// 预算改小后再告警=新口径新事实（同月第二次告警允许）
	if err := svc.SetBudget(ctx, "t-a", 10, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Record(ctx, rec("t-a", "mm", "m1", 20)); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 2 {
		t.Fatalf("预算口径变更后应重新告警: %+v", sink.alerts)
	}
}

func TestNoBudgetNoAlert(t *testing.T) {
	svc, _, sink := newSvc(t)
	if _, err := svc.Record(context.Background(), rec("t-a", "mm", "m1", 1<<20)); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 0 {
		t.Fatal("未设预算不得告警（如实标注不冒充管控）")
	}
}

func TestRecordValidation(t *testing.T) {
	svc, _, _ := newSvc(t)
	if _, err := svc.Record(context.Background(), Event{Tenant: "", TotalTokens: 1}); err == nil {
		t.Error("缺租户应拒绝")
	}
	if _, err := svc.Record(context.Background(), Event{Tenant: "t-a", TotalTokens: -1}); err == nil {
		t.Error("负 token 应拒绝")
	}
	if err := svc.SetBudget(context.Background(), "t-a", -5, "u1"); err == nil {
		t.Error("负预算应拒绝")
	}
	if err := svc.SetBudget(context.Background(), "t-a", 100, ""); err == nil {
		t.Error("设预算人必填（人在环）")
	}
}
