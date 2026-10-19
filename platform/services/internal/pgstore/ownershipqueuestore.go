// ownership.QueueStore 的 PostgreSQL 实现（014_review_queue.sql；V-4 人工复核队列落 PG）。
// 契约与内存版一致（C-6）：List 仅待复核；Save 按 (tenant_id,domain) 幂等并保留原 seq；
// Resolve 置 resolved + 留痕（行保留=复核历史可追溯，而非出队即消失）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

type OwnershipQueueStore struct{ db *DB }

func (d *DB) OwnershipQueue() *OwnershipQueueStore { return &OwnershipQueueStore{d} }

var _ ownership.QueueStore = (*OwnershipQueueStore)(nil)

func (s *OwnershipQueueStore) List(ctx context.Context) ([]ownership.QueueItem, error) {
	rs, err := s.db.sql.QueryContext(ctx,
		`SELECT seq, tenant_id, item FROM ownership_queue WHERE status='pending' ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []ownership.QueueItem
	for rs.Next() {
		var seq int64
		var tenant string
		var b []byte
		if err := rs.Scan(&seq, &tenant, &b); err != nil {
			return nil, err
		}
		var it ownership.QueueItem
		if err := json.Unmarshal(b, &it); err != nil {
			return nil, err
		}
		it.Seq = int(seq)
		it.Tenant = tenant // 列权威：JSONB 快照与租户列必须一致（行级闸以列为准）
		out = append(out, it)
	}
	return out, rs.Err()
}

func (s *OwnershipQueueStore) Save(ctx context.Context, it ownership.QueueItem) (int, error) {
	b, err := json.Marshal(it)
	if err != nil {
		return 0, err
	}
	// 幂等 upsert：同租户同域重复入队=刷新判决并回置待复核，保留原 seq（复核编号稳定）。
	var seq int64
	err = s.db.sql.QueryRowContext(ctx, `INSERT INTO ownership_queue(tenant_id,domain,item)
VALUES($1,$2,$3::jsonb)
ON CONFLICT (tenant_id,domain) DO UPDATE SET item=EXCLUDED.item, status='pending', resolved_by=NULL, resolved_at=NULL, ts=now()
RETURNING seq`, it.Tenant, it.Domain, b).Scan(&seq)
	if err != nil {
		return 0, err
	}
	return int(seq), nil
}

func (s *OwnershipQueueStore) Resolve(ctx context.Context, seq int, toVerdict, reviewer string, ts time.Time) error {
	// 读-改-写：判决与依据写入 JSONB 快照（复核留痕入快照），状态列置 resolved。
	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var b []byte
	if err := tx.QueryRowContext(ctx, `SELECT item FROM ownership_queue WHERE seq=$1 AND status='pending'`, seq).Scan(&b); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ownership.ErrQueueNotFound // 已复核/不存在=不可重复复核（防回执式覆盖）
		}
		return err
	}
	var it ownership.QueueItem
	if err := json.Unmarshal(b, &it); err != nil {
		return err
	}
	it.Verdict.Verdict = toVerdict
	it.Verdict.Reasons = append(it.Verdict.Reasons, "人工复核 "+reviewer+" → "+toVerdict)
	nb, err := json.Marshal(it)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE ownership_queue SET item=$2::jsonb, status='resolved', resolved_by=$3, resolved_at=$4 WHERE seq=$1`,
		seq, nb, reviewer, ts)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ownership.ErrQueueNotFound
	}
	return tx.Commit()
}
