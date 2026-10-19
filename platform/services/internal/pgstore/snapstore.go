// monitor.SnapStore 的 PostgreSQL 实现（008_diff.sql / FR-MON-002 diff 基线）。
// SaveSnapshot=全量同步：UPSERT 现存行 + DELETE 已消失行（快照=当前态镜像语义）。
package pgstore

import (
	"context"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

type SnapStore struct{ db *DB }

func (d *DB) Snapshots() *SnapStore { return &SnapStore{d} }

var _ monitor.SnapStore = (*SnapStore)(nil)

func (s *SnapStore) LoadSnapshot(ctx context.Context, tenant string) (map[string]string, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT asset_id, fp FROM asset_snapshots WHERE tenant_id=$1`, tenant)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string]string{}
	for rs.Next() {
		var id, f string
		if err := rs.Scan(&id, &f); err != nil {
			return nil, err
		}
		out[id] = f
	}
	return out, rs.Err()
}

func (s *SnapStore) SaveSnapshot(ctx context.Context, tenant string, snap map[string]string) error {
	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, f := range snap {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_snapshots(tenant_id,asset_id,fp,captured_at)
VALUES($1,$2,$3,now()) ON CONFLICT (tenant_id,asset_id)
DO UPDATE SET fp=EXCLUDED.fp, captured_at=now()`, tenant, id, f); err != nil {
			return err
		}
	}
	if len(snap) == 0 { // 空快照=整租户清空（防把「全部消失」当基线保留）
		_, err = tx.ExecContext(ctx, `DELETE FROM asset_snapshots WHERE tenant_id=$1`, tenant)
	} else {
		ids := make([]string, 0, len(snap))
		for id := range snap {
			ids = append(ids, id)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM asset_snapshots WHERE tenant_id=$1 AND asset_id <> ALL($2)`,
			tenant, pq.Array(ids))
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
