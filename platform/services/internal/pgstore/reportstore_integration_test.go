package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/report"
)

// 为什么（013=报告历史的持久载体）：报告是对外交付物，生成记录不得随进程蒸发
// （审查 P2-1：MemStore 重启清空与其余已落 PG 域不一致）。双连接=跨进程视角；
// Get 行级闸：跨租户与不存在同为 ErrNotFound（报告含客户名与风险明细，AX-5）。
func TestReportStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-rpt"
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM reports WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)

	base := report.Report{
		ID: "RPT-itest-1", Tenant: tid, TenantName: "集成测试客户", Period: report.PeriodD7,
		Audience: report.AudExec, Sections: report.SectionOrder,
		PeriodFrom: time.Now().UTC().Add(-7 * 24 * time.Hour), PeriodTo: time.Now().UTC(),
		GeneratedAt: time.Now().UTC(), Text: "# 执行摘要\n0 项", ContentHash: "sha256:itest",
	}
	if err := db.Reports().Save(ctx, base); err != nil {
		t.Fatal(err)
	}
	// 同 id 重放=覆盖刷新（与 MemStore.Save 覆盖语义一致；编号幂等内容取最新事实）
	const updatedText = "# 执行摘要\n1 项"
	base.Text = updatedText
	if err := db.Reports().Save(ctx, base); err != nil {
		t.Fatal(err)
	}

	// 独立连接读回（跨进程视角：重启后历史仍在）
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	got, err := db2.Reports().Get(ctx, tid, "RPT-itest-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != updatedText || got.TenantName != base.TenantName || got.ContentHash != base.ContentHash || len(got.Sections) != len(report.SectionOrder) {
		t.Errorf("跨连接回读失真: %+v", got)
	}
	list, err := db2.Reports().List(ctx, tid)
	if err != nil || len(list) != 1 {
		t.Errorf("列表错误: %v %d", err, len(list))
	}
	// 行级闸：跨租户与不存在同为 ErrNotFound
	if _, err := db2.Reports().Get(ctx, "itest-other", "RPT-itest-1"); err != report.ErrNotFound {
		t.Errorf("跨租户应 ErrNotFound: %v", err)
	}
	if _, err := db2.Reports().Get(ctx, tid, "RPT-ghost"); err != report.ErrNotFound {
		t.Errorf("不存在 id 应 ErrNotFound: %v", err)
	}
	if l, err := db2.Reports().List(ctx, "itest-other"); err != nil || len(l) != 0 {
		t.Errorf("跨租户列表应为空: %v %d", err, len(l))
	}
}
