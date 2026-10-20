package pgstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// MonitorTaskStore 实现 monitor.TaskStore（021 / M4-03 / FR-MON-003）。
// 契约：同源 pending 单收敛刷新（UPDATE … WHERE status='pending'，ON CONFLICT 兜底部分唯一索引）；
// done 终态可再触发=新行；ListTasks/DoneTask 事务内 withTenant（RLS GUC + 显式谓词）。
type MonitorTaskStore struct{ db *DB }

// MonitorTasks 派生任务单 store。
func (d *DB) MonitorTasks() *MonitorTaskStore { return &MonitorTaskStore{d} }

// AddTask 幂等开单：pending 同源单已存在→收敛刷新（created=false）；否则 INSERT。
func (st *MonitorTaskStore) AddTask(ctx context.Context, tk monitor.Task) (bool, error) {
	created := false
	err := st.db.withTenant(ctx, tk.Tenant, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE monitor_tasks SET reason=$1, asset_name=$2, created_at=COALESCE($3, now())
WHERE tenant_id=$4 AND asset_id=$5 AND trigger=$6 AND status='pending'`,
			tk.Reason, tk.AssetName, nullTime(tk.CreatedAt), tk.Tenant, tk.AssetID, tk.Trigger)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil // 收敛刷新命中，不开新行
		}
		if _, err := tx.Exec(`INSERT INTO monitor_tasks
(id,tenant_id,asset_id,asset_name,trigger,reason,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,'pending',COALESCE($7, now()))`,
			tk.ID, tk.Tenant, tk.AssetID, tk.AssetName, tk.Trigger, tk.Reason, nullTime(tk.CreatedAt)); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

// ListTasks 查询（status 空=全部；最新在前）。
func (st *MonitorTaskStore) ListTasks(ctx context.Context, tenant, status string) ([]monitor.Task, error) {
	var out []monitor.Task
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		q := `SELECT id,tenant_id,asset_id,asset_name,trigger,reason,status,by_whom,note,created_at,done_at
FROM monitor_tasks WHERE tenant_id=$1`
		args := []any{tenant}
		if status != "" {
			q += " AND status=$2"
			args = append(args, status)
		}
		q += " ORDER BY created_at DESC, id DESC"
		rs, err := tx.Query(q, args...)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var (
				tk             monitor.Task
				name, by, note sql.NullString
				doneAt         sql.NullTime
			)
			if err := rs.Scan(&tk.ID, &tk.Tenant, &tk.AssetID, &name, &tk.Trigger, &tk.Reason,
				&tk.Status, &by, &note, &tk.CreatedAt, &doneAt); err != nil {
				return err
			}
			tk.AssetName, tk.By, tk.Note = nz(name), nz(by), nz(note)
			if doneAt.Valid {
				d := doneAt.Time
				tk.DoneAt = &d
			}
			out = append(out, tk)
		}
		return rs.Err()
	})
	return out, err
}

// DoneTask 闭环（仅 pending→done；不存在=ErrTaskNotFound；已闭环=ErrTaskClosed）。
func (st *MonitorTaskStore) DoneTask(ctx context.Context, tenant, id, by, note string) (monitor.Task, error) {
	var out monitor.Task
	err := st.db.withTenant(ctx, tenant, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRow(`SELECT status FROM monitor_tasks WHERE id=$1 AND tenant_id=$2`, id, tenant).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return monitor.ErrTaskNotFound
		}
		if err != nil {
			return err
		}
		if status == "done" {
			return monitor.ErrTaskClosed
		}
		var name, byCol, noteCol sql.NullString
		var doneAt sql.NullTime
		if err := tx.QueryRow(`UPDATE monitor_tasks
SET status='done', by_whom=$1, note=$2, done_at=now() WHERE id=$3 AND tenant_id=$4
RETURNING id,tenant_id,asset_id,asset_name,trigger,reason,status,by_whom,note,created_at,done_at`,
			by, note, id, tenant).Scan(&out.ID, &out.Tenant, &out.AssetID, &name, &out.Trigger,
			&out.Reason, &out.Status, &byCol, &noteCol, &out.CreatedAt, &doneAt); err != nil {
			return err
		}
		out.AssetName, out.By, out.Note = nz(name), nz(byCol), nz(noteCol)
		if doneAt.Valid {
			d := doneAt.Time
			out.DoneAt = &d
		}
		return nil
	})
	if err != nil {
		return monitor.Task{}, err
	}
	return out, nil
}
