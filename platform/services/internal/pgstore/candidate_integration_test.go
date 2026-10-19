package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
)

// 为什么（V-4=unsupported 复核队列持久载体）：被拒候选行携带原文+拒绝原因，
// 是「不静默丢弃」的界面锚点——跨重启丢失=坏行悄悄消失，渠道接入后无从复核。
// 双连接=跨进程视角；去重键=(line,error) 幂等=重放/重试不重复入队。
func TestCandidateUnsupportedStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cleanup := func() {
		_, _ = db.sql.Exec(`DELETE FROM candidate_unsupported WHERE line LIKE 'itest-%'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	u1 := candidate.Unsupported{Line: "itest-line-1", Error: "candidate: 必填缺失 kind", Channel: "port.scan"}
	u2 := candidate.Unsupported{Line: "itest-line-2", Error: "越权租户 t-x", Channel: ""}
	if err := db.Candidates().Save(ctx, u1); err != nil {
		t.Fatal(err)
	}
	if err := db.Candidates().Save(ctx, u2); err != nil {
		t.Fatal(err)
	}
	// 同原文同原因重放=不重复入队（摄取幂等友好）
	if err := db.Candidates().Save(ctx, u1); err != nil {
		t.Fatal(err)
	}

	// 独立连接读回（跨进程视角）
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	rows, err := db2.Candidates().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	var got candidate.Unsupported
	for _, r := range rows {
		if r.Line == "itest-line-1" {
			got = r
			n++
		}
	}
	if n != 1 {
		t.Fatalf("重复保存应去重为 1 行: %d", n)
	}
	if got.Error != u1.Error || got.Channel != u1.Channel || got.Line != u1.Line {
		t.Errorf("回读失真: %+v", got)
	}
}

// 为什么（V-9）：摄取留痕是投喂历史的审计事实——双连接读回验证跨进程/跨重启可查，
// 且 ON CONFLICT DO NOTHING 保证同一原始行重复摄取不产生第二份留痕。
func TestCandidateAcceptedStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cleanup := func() {
		_, _ = db.sql.Exec(`DELETE FROM candidate_accepted WHERE tenant_id='itest-ca'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	line := `{"kind":"finding","tenant_id":"itest-ca","sub_code":"SCAN-1","channel":"port.scan","finding":{"title":"备份可下载","category":"代码密码类","risk":"高"},"evidence":{"ts":"2026-10-18T00:00:00Z"}}`
	rec := candidate.AcceptedRecord{
		Key: candidate.AcceptedKey(line), TenantID: "itest-ca", Kind: "finding",
		SubCode: "SCAN-1", Channel: "port.scan",
		TS: time.Now().UTC(), AcceptedAt: time.Now().UTC(), Line: line,
	}
	if err := db.Candidates().SaveAccepted(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// 重放同键=不重复入队
	if err := db.Candidates().SaveAccepted(ctx, rec); err != nil {
		t.Fatal(err)
	}

	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	rows, err := db2.Candidates().ListAccepted(ctx, "itest-ca")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("重复保存应去重为 1 行: %d", len(rows))
	}
	if rows[0].Line != line || rows[0].TenantID != "itest-ca" || rows[0].Kind != "finding" || rows[0].TS.IsZero() {
		t.Errorf("回读失真: %+v", rows[0])
	}
	// 他租户不可见（行级口径）
	other, err := db2.Candidates().ListAccepted(ctx, "itest-other")
	if err != nil || len(other) != 0 {
		t.Errorf("他租户留痕应不可见: %v %d", err, len(other))
	}
}
