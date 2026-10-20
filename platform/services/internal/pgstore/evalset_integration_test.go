package pgstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
)

// 为什么（M3-E / 019）：评测样本与运行记录是门禁证据面，双后端必须同契约——
// 幂等语义（PutSample 不覆盖标注）、追加式二次标注、运行历史最新在前。
// 与内存实现跑同一组操作对账（C-6）。
func TestEvalSetStoreRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Open(kbDSN(t)) // 第二「进程」
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, st2 := db.EvalSet(), db2.EvalSet()
	t.Cleanup(func() {
		_, _ = db.sql.Exec(`DELETE FROM evalset_promotes WHERE tenant_id LIKE 'itest%'`)
		_, _ = db.sql.Exec(`DELETE FROM evalset_samples WHERE tenant_id LIKE 'itest%'`)
		_, _ = db.sql.Exec(`DELETE FROM evalset_runs WHERE tenant_id LIKE 'itest%'`)
	})
	_, _ = db.sql.Exec(`DELETE FROM evalset_promotes WHERE tenant_id LIKE 'itest%'`)
	_, _ = db.sql.Exec(`DELETE FROM evalset_samples WHERE tenant_id LIKE 'itest%'`)
	_, _ = db.sql.Exec(`DELETE FROM evalset_runs WHERE tenant_id LIKE 'itest%'`)

	sm := evalset.Sample{
		ID: "EV-itest0001", Tenant: "itest-eval", Kind: evalset.KindSens,
		Text: "-----BEGIN RSA PRIVATE KEY-----", Expected: true,
		ExpectedBy: "u1", Source: evalset.SourceManual, CreatedAt: time.Now().UTC(),
	}
	created, err := st.PutSample(ctx, sm)
	if err != nil || !created {
		t.Fatalf("首写应 created: %v %v", created, err)
	}
	created2, _ := st2.PutSample(ctx, sm) // 跨连接=跨进程幂等
	if created2 {
		t.Fatal("重复写应 created=false（不覆盖既有标注）")
	}
	ls, err := st2.ListSamples(ctx, "itest-eval")
	if err != nil || len(ls) != 1 || ls[0].Text != sm.Text || ls[0].ExpectedBy != "u1" {
		t.Fatalf("跨进程回读样本失败: %+v %v", ls, err)
	}
	// 追加式二次标注（跨进程可见，历史不改写）
	rl := evalset.Relabel{By: "u2", Expected: true, TS: time.Now().UTC()}
	if err := st2.AppendRelabel(ctx, "itest-eval", sm.ID, rl); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendRelabel(ctx, "itest-eval", "EV-nope", rl); !errors.Is(err, evalset.ErrSampleNotFound) {
		t.Fatalf("不存在样本应 ErrSampleNotFound，实际 %v", err)
	}
	ls2, _ := st.ListSamples(ctx, "itest-eval")
	if len(ls2[0].Relabels) != 1 || ls2[0].Relabels[0].By != "u2" {
		t.Fatalf("二次标注未跨进程落库: %+v", ls2[0].Relabels)
	}
	// 运行记录：最新在前 + payload 完整回读
	run := evalset.Run{
		ID: "ER-itest0001", Tenant: "itest-eval", Subject: "classify-22rules",
		TS: time.Now().UTC(), Total: 1, Precision: 1, Recall: 1, F1: 1, Accuracy: 1,
		Gate: evalset.GateDecision{Allow: false, Reasons: []string{"样本 1 < 最小 30"}},
	}
	if err := st.PutRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	rs, err := st2.ListRuns(ctx, "itest-eval", 10)
	if err != nil || len(rs) != 1 || rs[0].ID != run.ID || rs[0].Total != 1 ||
		len(rs[0].Gate.Reasons) != 1 {
		t.Fatalf("运行记录跨进程回读失败: %+v %v", rs, err)
	}
	// 放量留痕（020 / ENH-03）：跨进程落痕 + 阈值口径快照回读
	p := evalset.Promote{
		ID: "EP-itest0001", Tenant: "itest-eval", RunID: run.ID, GateAllow: true,
		Reasons: []string{}, Thresholds: evalset.DefaultThresholds(),
		By: "u1", Note: "灰度放量示证", TS: time.Now().UTC(),
	}
	if err := st.PutPromote(ctx, p); err != nil {
		t.Fatal(err)
	}
	ps, err := st2.ListPromotes(ctx, "itest-eval", 10)
	if err != nil || len(ps) != 1 || ps[0].ID != p.ID || ps[0].RunID != run.ID ||
		!ps[0].GateAllow || ps[0].By != "u1" || ps[0].Thresholds != evalset.DefaultThresholds() {
		t.Fatalf("放量留痕跨进程回读失败: %+v %v", ps, err)
	}
}
