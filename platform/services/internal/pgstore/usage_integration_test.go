package pgstore

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
)

// 为什么（M4-07 / 022）：计量与预算=FR-HRN-10 事实源，双后端必须同契约——
// 事件留痕跨进程可查、预算租户一行（口径变更清告警标记）、当月告警标记置位/清除。
func TestUsageStoreRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Open(kbDSN(t)) // 第二「进程」
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, st2 := db.Usage(), db2.Usage()
	t.Cleanup(func() {
		_, _ = db.sql.Exec(`DELETE FROM usage_events WHERE tenant_id LIKE 'itest%'`)
		_, _ = db.sql.Exec(`DELETE FROM usage_budgets WHERE tenant_id LIKE 'itest%'`)
	})
	_, _ = db.sql.Exec(`DELETE FROM usage_events WHERE tenant_id LIKE 'itest%'`)
	_, _ = db.sql.Exec(`DELETE FROM usage_budgets WHERE tenant_id LIKE 'itest%'`)

	now := time.Now().UTC()
	for i, total := range []int64{100, 50, 30} {
		if err := st.AddEvent(ctx, usage.Event{
			ID: "UE-itest000" + string(rune('1'+i)), Tenant: "itest-use", Feature: "mm", Model: "m1",
			PromptTokens: total / 2, CompletionTokens: total - total/2, TotalTokens: total, TS: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// 跨进程汇总
	sum, err := st2.SumRange(ctx, "itest-use", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil || sum.Calls != 3 || sum.TotalTokens != 180 || sum.ByFeature["mm"] != 180 || sum.ByModel["m1"] != 180 {
		t.Fatalf("跨进程汇总: %+v %v", sum, err)
	}
	// 租户隔离
	sumB, _ := st.SumRange(ctx, "itest-other", now.Add(-time.Hour), now.Add(time.Hour))
	if sumB.TotalTokens != 0 {
		t.Fatalf("跨租户串数: %+v", sumB)
	}
	// 预算：设置→读取→超线告警标记→清标
	if err := st.SetBudget(ctx, "itest-use", 150, "u1"); err != nil {
		t.Fatal(err)
	}
	b, by, _, ok, err := st2.GetBudget(ctx, "itest-use")
	if err != nil || !ok || b != 150 || by != "u1" {
		t.Fatalf("预算跨进程读取: %d %s %v %v", b, by, ok, err)
	}
	if err := st.MarkBudgetAlert(ctx, "itest-use", now.Format("2006-01")); err != nil {
		t.Fatal(err)
	}
	marked, _ := st2.BudgetAlertMarked(ctx, "itest-use", now.Format("2006-01"))
	if !marked {
		t.Fatal("当月告警标记应置位（跨进程）")
	}
	// 口径变更=清标（新口径新事实）
	if err := st.SetBudget(ctx, "itest-use", 10, "u1"); err != nil {
		t.Fatal(err)
	}
	marked2, _ := st.BudgetAlertMarked(ctx, "itest-use", now.Format("2006-01"))
	if marked2 {
		t.Fatal("口径变更应清告警标记")
	}
}
