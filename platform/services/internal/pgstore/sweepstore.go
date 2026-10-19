// sweep.Store 的 PostgreSQL 实现（006_sweeps.sql / ENH-01 跨进程事实源）。
// steps/phases 以 JSONB/text[] 承载；Save=upsert（断点进度追加语义）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
)

type SweepStore struct{ db *DB }

func (d *DB) Sweeps() *SweepStore { return &SweepStore{d} }

var _ sweep.Store = (*SweepStore)(nil)

func (s *SweepStore) Save(ctx context.Context, sw *sweep.Sweep) error {
	steps, err := json.Marshal(sw.Steps)
	if err != nil {
		return err
	}
	if string(steps) == "null" {
		steps = []byte("[]") // 空进度=空数组（jsonb_array_length 可计算；C-6 与内存契约一致）
	}
	// 进度追加语义：保留首次派发时间（worker/重复 Save 不得覆盖 started_at）
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO sweeps
(id,tenant_id,phases,status,steps,findings,error,started_at,ended_at)
VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)
ON CONFLICT (id) DO UPDATE
SET status=EXCLUDED.status, steps=EXCLUDED.steps, findings=EXCLUDED.findings,
    error=EXCLUDED.error, ended_at=EXCLUDED.ended_at, updated_at=now()`,
		sw.ID, sw.Tenant, pq.Array(textArr(sw.Phases)), sw.Status, steps,
		sw.Findings, sw.Error, sw.StartedAt, sw.EndedAt)
	return err
}

func scanSweep(row interface{ Scan(dest ...any) error }) (sweep.Sweep, error) {
	var (
		sw     sweep.Sweep
		stepsB []byte
		phases pq.StringArray
		end    sql.NullTime
		err    sql.NullString
	)
	if err := row.Scan(&sw.ID, &sw.Tenant, &phases, &sw.Status, &stepsB, &sw.Findings, &err, &sw.StartedAt, &end); err != nil {
		return sweep.Sweep{}, err
	}
	sw.Phases = []string(phases)
	if err := json.Unmarshal(stepsB, &sw.Steps); err != nil {
		return sweep.Sweep{}, err
	}
	sw.Error = nz(err)
	if end.Valid {
		sw.EndedAt = &end.Time
	}
	return sw, nil
}

const sweepCols = `id,tenant_id,phases,status,steps,findings,error,started_at,ended_at`

func (s *SweepStore) Get(ctx context.Context, id string) (sweep.Sweep, bool, error) {
	row := s.db.sql.QueryRowContext(ctx, `SELECT `+sweepCols+` FROM sweeps WHERE id=$1`, id)
	sw, err := scanSweep(row)
	if errors.Is(err, sql.ErrNoRows) {
		return sweep.Sweep{}, false, nil
	}
	if err != nil {
		return sweep.Sweep{}, false, err
	}
	return sw, true, nil
}

func (s *SweepStore) List(ctx context.Context, tenant string) ([]sweep.Sweep, error) {
	q := `SELECT ` + sweepCols + ` FROM sweeps`
	var args []any
	if tenant != "" {
		q += ` WHERE tenant_id=$1`
		args = append(args, tenant)
	}
	q += ` ORDER BY id DESC`
	rs, err := s.db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []sweep.Sweep
	for rs.Next() {
		sw, err := scanSweep(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rs.Err()
}
