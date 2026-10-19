package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

// 为什么（V-4=人工复核队列持久载体）：疑似/无关样本是暗网兜底的防污染锚点，
// 复核动作与留痕必须跨进程恢复——重启后「待复核」队列与已复核历史一条不能丢。
// 双连接=跨进程视角；(tenant_id,domain) 幂等=重复入队不得刷出第二项（复核编号稳定）。
func TestOwnershipQueueStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tid := "itest-oq"
	cleanup := func() { _, _ = db.sql.Exec(`DELETE FROM ownership_queue WHERE tenant_id=$1`, tid) }
	cleanup()
	t.Cleanup(cleanup)

	mk := func(domain string, v ownership.Verdict) ownership.QueueItem {
		return ownership.QueueItem{Tenant: tid, Domain: domain, Verdict: v}
	}
	v1 := ownership.Verdict{Domain: "leak.onion", Verdict: ownership.VerdictSuspect, Confidence: 0.5, Reasons: []string{"关键词共现 2 次"}}
	seq1, err := db.OwnershipQueue().Save(ctx, mk("leak.onion", v1))
	if err != nil {
		t.Fatal(err)
	}
	// 重复入队同租户同域=保留原 seq、刷新判决（不得刷出第二项）
	v1b := ownership.Verdict{Domain: "leak.onion", Verdict: ownership.VerdictSuspect, Confidence: 0.45, Reasons: []string{"证书指纹无基线"}}
	seq1b, err := db.OwnershipQueue().Save(ctx, mk("leak.onion", v1b))
	if err != nil {
		t.Fatal(err)
	}
	if seq1b != seq1 {
		t.Errorf("重复入队应保留原 seq: %d != %d", seq1b, seq1)
	}
	v2 := ownership.Verdict{Domain: "other.onion", Verdict: ownership.VerdictUnrelated, Confidence: 0.9}
	seq2, err := db.OwnershipQueue().Save(ctx, mk("other.onion", v2))
	if err != nil {
		t.Fatal(err)
	}
	if seq2 == seq1 {
		t.Errorf("不同域应分配新 seq: %d", seq2)
	}

	// 独立连接读回（跨进程视角：重启后队列仍在）
	db2, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.sql.Close()
	rows, err := db2.OwnershipQueue().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got1, got2 ownership.QueueItem
	for _, r := range rows {
		if r.Tenant == tid && r.Domain == "leak.onion" {
			got1 = r
		}
		if r.Tenant == tid && r.Domain == "other.onion" {
			got2 = r
		}
	}
	if got1.Seq != int(seq1) || got1.Tenant != tid || len(got1.Verdict.Reasons) != 1 || got1.Verdict.Reasons[0] != "证书指纹无基线" {
		t.Errorf("水化回读失真（判决应刷新、seq 应稳定）: %+v", got1)
	}
	if got2.Verdict.Verdict != ownership.VerdictUnrelated {
		t.Errorf("第二项回读失真: %+v", got2)
	}

	// 复核出口：留痕 + 出 pending；重复复核=ErrQueueNotFound（防回执式覆盖）
	if err := db2.OwnershipQueue().Resolve(ctx, int(seq1), ownership.VerdictOwned, "复核人A", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := db2.OwnershipQueue().Resolve(ctx, int(seq1), ownership.VerdictOwned, "复核人B", time.Now().UTC()); err != ownership.ErrQueueNotFound {
		t.Errorf("重复复核应 ErrQueueNotFound: %v", err)
	}
	rows, err = db2.OwnershipQueue().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Tenant == tid && r.Domain == "leak.onion" {
			t.Errorf("已复核项不应再出现在待复核面: %+v", r)
		}
	}
	// 行保留=复核历史可追溯（resolved 行仍在库中，仅出 pending 面）
	var status string
	if err := db2.sql.QueryRowContext(ctx, `SELECT status FROM ownership_queue WHERE seq=$1`, seq1).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" {
		t.Errorf("复核行应置 resolved（留痕保留）: %s", status)
	}
}
