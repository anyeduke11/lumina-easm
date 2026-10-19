// report.Store 的 PostgreSQL 实现（013_report.sql；V-3 报告历史 PG 化）。
// 报告=对外交付物快照：ID 确定性（RPT-<hash12(tenant|period|audience|sections|from)>），
// 同参数同窗重放=覆盖刷新（UPSERT，与 MemStore.Save 的覆盖语义一致，C-6 同契约）；
// Get 以 tenant+id 双条件行级过滤（跨租户与不存在同为 ErrNotFound，AX-5 不泄露存在性）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/wangdev88/easm-platform/platform/services/internal/report"
)

type ReportStore struct{ db *DB }

func (d *DB) Reports() *ReportStore { return &ReportStore{d} }

var _ report.Store = (*ReportStore)(nil)

func (s *ReportStore) Save(ctx context.Context, r report.Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO reports(id,tenant_id,r) VALUES($1,$2,$3::jsonb)
ON CONFLICT (id) DO UPDATE SET r=EXCLUDED.r`, r.ID, r.Tenant, b)
	return err
}

func (s *ReportStore) Get(ctx context.Context, tenant, id string) (report.Report, error) {
	var b []byte
	err := s.db.sql.QueryRowContext(ctx, `SELECT r FROM reports WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return report.Report{}, report.ErrNotFound
	}
	if err != nil {
		return report.Report{}, err
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return report.Report{}, err
	}
	return r, nil
}

func (s *ReportStore) List(ctx context.Context, tenant string) ([]report.Report, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT r FROM reports WHERE tenant_id=$1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []report.Report
	for rs.Next() {
		var b []byte
		if err := rs.Scan(&b); err != nil {
			return nil, err
		}
		var r report.Report
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}
