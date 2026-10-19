package pgstore

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// 为什么（008 / FR-MON-002）：diff 基线必须跨进程持久（Temporal worker 与 server 都要看到
// 同一份上次快照）；Save=当前态镜像（UPSERT+DELETE 消失行）——测试锁定该语义。
func TestSnapStoreRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	db2, err := Open(kbDSN(t)) // 第二「进程」
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, st2 := db.Snapshots(), db2.Snapshots()
	t.Cleanup(func() { _, _ = db.sql.Exec(`DELETE FROM asset_snapshots WHERE tenant_id LIKE 'itest%'`) })
	_, _ = db.sql.Exec(`DELETE FROM asset_snapshots WHERE tenant_id LIKE 'itest%'`)

	snap := map[string]string{"x1": "fp-a", "x2": "fp-b"}
	if err := st.SaveSnapshot(ctx, "itest-diff", snap); err != nil {
		t.Fatal(err)
	}
	got, err := st2.LoadSnapshot(ctx, "itest-diff") // 跨连接=跨进程视角
	if err != nil || len(got) != 2 || got["x1"] != "fp-a" {
		t.Fatalf("跨进程回读失败: %v %v", got, err)
	}
	// 当前态镜像：x1 变更、x2 移除
	if err := st.SaveSnapshot(ctx, "itest-diff", map[string]string{"x1": "fp-a2"}); err != nil {
		t.Fatal(err)
	}
	got2, _ := st2.LoadSnapshot(ctx, "itest-diff")
	if len(got2) != 1 || got2["x1"] != "fp-a2" {
		t.Errorf("消失行未 DELETE: %v", got2)
	}
	var _ monitor.SnapStore = st
}
