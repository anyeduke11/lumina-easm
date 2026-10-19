package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
)

// EvalSetStore 实现 evalset.Store（019 / M3-E 评测集与反馈门禁）。
//
// 契约：样本按确定性 ID 幂等（PutSample 不覆盖既有标注）；二次标注追加式
// （relabels jsonb || 追加，复核历史可追溯）；运行记录按 ts 倒序（最近一次=门禁对象）。
// 全部查询在 withTenant 事务内（RLS GUC + 显式 tenant_id 谓词，双保险）。
type EvalSetStore struct{ db *DB }

// EvalSet 派生评测集 store。
func (d *DB) EvalSet() *EvalSetStore { return &EvalSetStore{d} }

const evalSampleCols = `id,tenant_id,kind,content,expected,expected_by,evidence_ref,ledger_id,source,relabels,created_at`

func scanEvalSample(row interface{ Scan(dest ...any) error }) (evalset.Sample, error) {
	var (
		s       evalset.Sample
		ev, led sql.NullString
		rls     []byte
	)
	err := row.Scan(&s.ID, &s.Tenant, &s.Kind, &s.Text, &s.Expected, &s.ExpectedBy,
		&ev, &led, &s.Source, &rls, &s.CreatedAt)
	s.EvidenceRef, s.LedgerID = nz(ev), nz(led)
	if len(rls) > 0 {
		_ = json.Unmarshal(rls, &s.Relabels)
	}
	return s, err
}

// PutSample 幂等写入（ON CONFLICT DO NOTHING；同 ID 不覆盖既有标注）。
func (st *EvalSetStore) PutSample(ctx context.Context, s evalset.Sample) (bool, error) {
	created := false
	err := st.db.withTenant(ctx, s.Tenant, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRow(`INSERT INTO evalset_samples
(id,tenant_id,kind,content,expected,expected_by,evidence_ref,ledger_id,source,relabels,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11, now()))
ON CONFLICT (id) DO NOTHING RETURNING id`,
			s.ID, s.Tenant, s.Kind, s.Text, s.Expected, s.ExpectedBy,
			s.EvidenceRef, s.LedgerID, s.Source, `[]`, nullTime(s.CreatedAt)).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // 已存在：created=false（幂等重放）
		}
		if err == nil {
			created = true
		}
		return err
	})
	return created, err
}

// ListSamples 本租户全部样本（按 ID 排序，与内存实现同序=确定性输出）。
func (st *EvalSetStore) ListSamples(ctx context.Context, tenant string) ([]evalset.Sample, error) {
	var out []evalset.Sample
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		rs, err := tx.Query(`SELECT `+evalSampleCols+` FROM evalset_samples
WHERE tenant_id=$1 ORDER BY id`, tenant)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			s, err := scanEvalSample(rs)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rs.Err()
	})
	return out, err
}

// AppendRelabel 追加二次标注（jsonb 追加，不改写历史标注）。
func (st *EvalSetStore) AppendRelabel(ctx context.Context, tenant, sampleID string, rl evalset.Relabel) error {
	raw, err := json.Marshal(rl)
	if err != nil {
		return err
	}
	return st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE evalset_samples
SET relabels = relabels || $1::jsonb WHERE id=$2 AND tenant_id=$3`, raw, sampleID, tenant)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return evalset.ErrSampleNotFound
		}
		return nil
	})
}

// PutRun 追加运行记录（payload=完整 Run 单一真相；列仅承担排序/统计索引）。
func (st *EvalSetStore) PutRun(ctx context.Context, r evalset.Run) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return st.db.withTenant(ctx, r.Tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO evalset_runs (id,tenant_id,subject,total,payload,ts)
VALUES ($1,$2,$3,$4,$5,COALESCE($6, now()))
ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload`,
			r.ID, r.Tenant, r.Subject, r.Total, raw, nullTime(r.TS))
		return err
	})
}

// ListRuns 运行历史（最新在前；limit 上限 500 由调用侧保证，此处硬顶）。
func (st *EvalSetStore) ListRuns(ctx context.Context, tenant string, limit int) ([]evalset.Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 20
	}
	var out []evalset.Run
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		rs, err := tx.Query(`SELECT payload FROM evalset_runs
WHERE tenant_id=$1 ORDER BY ts DESC, id DESC LIMIT $2`, tenant, limit)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var raw []byte
			var r evalset.Run
			if err := rs.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rs.Err()
	})
	return out, err
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

var _ evalset.Store = (*EvalSetStore)(nil)
