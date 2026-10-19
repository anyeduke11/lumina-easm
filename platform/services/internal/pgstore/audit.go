// 审计日志 PG 落地（NFR-SEC-006 / CR-001~007）：easm_app 对 audit_logs 仅 INSERT+SELECT
// （002 迁移），数据库层保证仅追加；本类型只做写入与按租户读取。
package pgstore

import (
	"context"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func nowUTC() time.Time { return time.Now().UTC() }

type PGAudit struct{ db *DB }

func (d *DB) Audit() *PGAudit { return &PGAudit{d} }

func (a *PGAudit) Append(ctx context.Context, e audit.Entry) error {
	if e.TS.IsZero() {
		e.TS = nowUTC()
	}
	_, err := a.db.sql.ExecContext(ctx,
		`INSERT INTO audit_logs (ts, actor, action, tenant_id, resource, result, request_id)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		e.TS, e.Actor, e.Action, nullStr(e.TenantID), nullStr(e.Resource), e.Result, nullStr(e.RequestID))
	return err
}

// Recent 按租户读取最近审计（FR-UX-005 审计检索的 MVP 子集）。
// tenantID == "*"（仅管理角色经 Service 判权后使用）返回全部。
func (a *PGAudit) Recent(ctx context.Context, tenantID string, limit int) ([]audit.Entry, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT ts, actor, action, coalesce(tenant_id,''), coalesce(resource,''), result, coalesce(request_id,'')
FROM audit_logs`
	var args []any
	if tenantID == "*" {
		q += ` ORDER BY id DESC LIMIT $1`
		args = []any{limit}
	} else {
		q += ` WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2`
		args = []any{tenantID, limit}
	}
	rs, err := a.db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []audit.Entry
	for rs.Next() {
		var e audit.Entry
		if err := rs.Scan(&e.TS, &e.Actor, &e.Action, &e.TenantID, &e.Resource, &e.Result, &e.RequestID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rs.Err()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
