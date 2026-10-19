// workorder.Store 的 PostgreSQL 实现（011_workorder.sql；整行 JSONB + status 列同步）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

type WorkOrderStore struct{ db *DB }

func (d *DB) WorkOrders() *WorkOrderStore { return &WorkOrderStore{d} }

var _ workorder.Store = (*WorkOrderStore)(nil)

func (s *WorkOrderStore) Create(ctx context.Context, w workorder.WorkOrder) error {
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO work_orders(id,tenant_id,status,wo) VALUES($1,$2,$3,$4::jsonb)`,
		w.ID, w.Tenant, w.Status, b)
	if isDup(err) {
		return workorder.ErrDuplicate
	}
	return err
}

func (s *WorkOrderStore) Get(ctx context.Context, tenant, id string) (workorder.WorkOrder, error) {
	// 租户+ID 双条件：跨租户与不存在同响应=不泄露工单存在性（AX-5；工单含泄露载体 URL）
	var b []byte
	err := s.db.sql.QueryRowContext(ctx, `SELECT wo FROM work_orders WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return workorder.WorkOrder{}, workorder.ErrNotFound
	}
	if err != nil {
		return workorder.WorkOrder{}, err
	}
	var w workorder.WorkOrder
	if err := json.Unmarshal(b, &w); err != nil {
		return workorder.WorkOrder{}, err
	}
	return w, nil
}

func (s *WorkOrderStore) Update(ctx context.Context, w workorder.WorkOrder) error {
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	// RowsAffected==0=行不存在或租户不匹配 → ErrNotFound（防静默 no-op：
	// 「更新了但没生效」的工单在跟催台显示旧状态=跟踪断裂）
	res, err := s.db.sql.ExecContext(ctx, `UPDATE work_orders SET status=$2, wo=$3::jsonb, updated_at=now() WHERE tenant_id=$4 AND id=$1`,
		w.ID, w.Status, b, w.Tenant)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return workorder.ErrNotFound
	}
	return nil
}

func (s *WorkOrderStore) List(ctx context.Context, tenant, status string) ([]workorder.WorkOrder, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT wo FROM work_orders WHERE tenant_id=$1 AND ($2='' OR status=$2) ORDER BY id`,
		tenant, status)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []workorder.WorkOrder
	for rs.Next() {
		var b []byte
		if err := rs.Scan(&b); err != nil {
			return nil, err
		}
		var w workorder.WorkOrder
		if err := json.Unmarshal(b, &w); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rs.Err()
}
