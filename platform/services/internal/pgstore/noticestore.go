// notice.Store 的 PostgreSQL 实现（012_notice.sql；整行 JSONB + 三要素列 + 状态/回执列）。
// 结构性锁定：UPDATE 语句**不写** target/material_hash/created_at 列——CR-002 三要素
// 一经生成即不可改写，即使调用方构造了被篡改的 Notice 也无法落库（不依赖上层自觉）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
)

type NoticeStore struct{ db *DB }

func (d *DB) Notices() *NoticeStore { return &NoticeStore{d} }

var _ notice.Store = (*NoticeStore)(nil)

func (s *NoticeStore) Create(ctx context.Context, n notice.Notice) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO notices
(id,tenant_id,ledger_id,target,status,material_hash,material_ref,receipt_no,submitted_at,n,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
		n.ID, n.Tenant, n.LedgerID, n.Target, n.Status, n.MaterialHash, n.MaterialRef,
		nullStr(n.ReceiptNo), nullTimePtr(n.SubmittedAt), b, n.CreatedAt)
	if isDup(err) {
		return notice.ErrDuplicate
	}
	return err
}

// noticeCols 读侧统一列集：三要素与租户/单号**取列不取 blob**——Update 语句根本不写这些列，
// 故即使调用方提交被篡改的 Notice，权威值仍以首次落库的列为准（CR-002 结构性锁定）。
const noticeCols = `n,tenant_id,id,target,material_hash,material_ref,created_at`

func (s *NoticeStore) Get(ctx context.Context, tenant, id string) (notice.Notice, error) {
	var (
		b                             []byte
		tid, pid, target, mhash, mref string
		created                       time.Time
	)
	err := s.db.sql.QueryRowContext(ctx, `SELECT `+noticeCols+` FROM notices WHERE tenant_id=$1 AND id=$2`, tenant, id).
		Scan(&b, &tid, &pid, &target, &mhash, &mref, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return notice.Notice{}, notice.ErrNotFound // 跨租户与不存在同响应=不泄露他方通报（AX-5）
	}
	if err != nil {
		return notice.Notice{}, err
	}
	return stampLocked(b, tid, target, mhash, mref, created)
}

func (s *NoticeStore) Update(ctx context.Context, n notice.Notice) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	res, err := s.db.sql.ExecContext(ctx, `UPDATE notices
SET status=$2, receipt_no=$3, submitted_at=$4, n=$5::jsonb, updated_at=now()
WHERE tenant_id=$6 AND id=$1`,
		n.ID, n.Status, nullStr(n.ReceiptNo), nullTimePtr(n.SubmittedAt), b, n.Tenant)
	if err != nil {
		return err
	}
	if cnt, err := res.RowsAffected(); err != nil {
		return err
	} else if cnt == 0 {
		return notice.ErrNotFound // 静默 no-op=催办台显示旧态（跟踪断裂）
	}
	return nil
}

func (s *NoticeStore) List(ctx context.Context, tenant, status string) ([]notice.Notice, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT `+noticeCols+` FROM notices
WHERE tenant_id=$1 AND ($2='' OR status=$2) ORDER BY created_at, id`, tenant, status)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []notice.Notice
	for rs.Next() {
		var (
			b                             []byte
			tid, pid, target, mhash, mref string
			created                       time.Time
		)
		_ = pid
		if err := rs.Scan(&b, &tid, &pid, &target, &mhash, &mref, &created); err != nil {
			return nil, err
		}
		n, err := stampLocked(b, tid, target, mhash, mref, created)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rs.Err()
}

// stampLocked 反序列化 blob 后用列值覆盖权威字段（单号/租户/目标/材料哈希/ref/时间戳）。
func stampLocked(b []byte, tenantID, target, mhash, mref string, created time.Time) (notice.Notice, error) {
	var n notice.Notice
	if err := json.Unmarshal(b, &n); err != nil {
		return notice.Notice{}, err
	}
	n.Tenant, n.Target, n.MaterialHash, n.MaterialRef, n.CreatedAt = tenantID, target, mhash, mref, created.UTC()
	return n, nil
}

func nullTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
