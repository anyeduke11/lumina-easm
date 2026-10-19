package pgstore

import (
	"context"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// 为什么（009 / FR-MON-004 跨重启）：server 重启后 dispatch 去重必须从 PG 恢复；
// 重复留痕必须幂等（唯一索引），历史可经第二连接审计回读。
func TestNotifyLogRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM notify_log WHERE channel='itest-hook'`) }
	cleanup()
	t.Cleanup(cleanup)

	l, l2 := db.NotifyLog(), db2.NotifyLog()
	if err := l.LogDispatch("itest-hook", []string{"itest-hook|k1", "itest-hook|k2"}); err != nil {
		t.Fatal(err)
	}
	if err := l.LogDispatch("itest-hook", []string{"itest-hook|k1"}); err != nil { // 重放幂等
		t.Fatal(err)
	}
	ks, err := l2.LoadedKeys("itest-hook")
	if err != nil || len(ks) != 2 {
		t.Fatalf("应 2 条唯一留痕，实际 %d %v", len(ks), err)
	}
	var n int
	_ = db.sql.QueryRowContext(ctx, `SELECT count(*) FROM notify_log WHERE channel=$1 AND alert_key='k1'`, "itest-hook").Scan(&n)
	if n != 1 {
		t.Error("alert_key 去前缀存储错误")
	}
}
