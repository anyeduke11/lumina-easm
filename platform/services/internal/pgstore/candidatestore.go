// candidate.Store 的 PostgreSQL 实现（014_review_queue.sql；V-4 unsupported 复核队列落 PG）。
// 去重键 = sha256(line|error)（同原文同原因=同一复核项）：摄取重放/重试不重复入队，
// 与内存版「行级拒绝即入队」语义一致（C-6）。
// V-9：同结构实现 candidate.AcceptedStore（016_candidate_accepted.sql 摄取留痕，
// 去重键 = sha256(原始行)；仅追加——应用层无改写/删除路径，留痕即审计事实）。
package pgstore

import (
	"context"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
)

type CandidateStore struct{ db *DB }

func (d *DB) Candidates() *CandidateStore { return &CandidateStore{d} }

var _ candidate.Store = (*CandidateStore)(nil)
var _ candidate.AcceptedStore = (*CandidateStore)(nil)

// ---- V-9：accepted 摄取留痕（端口方法名与 unsupported 消歧） ----

func (s *CandidateStore) SaveAccepted(ctx context.Context, a candidate.AcceptedRecord) error {
	_, err := s.db.sql.ExecContext(ctx, `INSERT INTO candidate_accepted
(key,tenant_id,kind,sub_code,channel,ts,accepted_at,line)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (key) DO NOTHING`,
		a.Key, a.TenantID, a.Kind, a.SubCode, a.Channel, a.TS, a.AcceptedAt, a.Line)
	return err
}

func (s *CandidateStore) ListAccepted(ctx context.Context, tenant string) ([]candidate.AcceptedRecord, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT key,tenant_id,kind,sub_code,channel,ts,accepted_at,line
FROM candidate_accepted WHERE ($1='' OR tenant_id=$1) ORDER BY accepted_at, key`, tenant)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []candidate.AcceptedRecord
	for rs.Next() {
		var a candidate.AcceptedRecord
		if err := rs.Scan(&a.Key, &a.TenantID, &a.Kind, &a.SubCode, &a.Channel, &a.TS, &a.AcceptedAt, &a.Line); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rs.Err()
}

func (s *CandidateStore) Save(ctx context.Context, u candidate.Unsupported) error {
	_, err := s.db.sql.ExecContext(ctx, `INSERT INTO candidate_unsupported(key,line,error,channel)
VALUES($1,$2,$3,$4) ON CONFLICT (key) DO NOTHING`,
		candidate.UnsupportedKey(u.Line, u.Error), u.Line, u.Error, u.Channel)
	return err
}

func (s *CandidateStore) List(ctx context.Context) ([]candidate.Unsupported, error) {
	rs, err := s.db.sql.QueryContext(ctx,
		`SELECT ts, line, error, channel FROM candidate_unsupported ORDER BY ts, key`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []candidate.Unsupported
	for rs.Next() {
		var u candidate.Unsupported
		if err := rs.Scan(&u.TS, &u.Line, &u.Error, &u.Channel); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rs.Err()
}
