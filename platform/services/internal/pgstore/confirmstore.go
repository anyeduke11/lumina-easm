// pgstore/confirmstore.go — 单用户高危动作确认持久化（024_confirmations.sql）。
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
)

// ConfirmStore 实现 confirm.Store。
type ConfirmStore struct{ db *DB }

// Confirmations 返回确认存储句柄（装配层注入 confirm.Service）。
func (d *DB) Confirmations() *ConfirmStore { return &ConfirmStore{d} }

var _ confirm.Store = (*ConfirmStore)(nil)

func (s *ConfirmStore) Create(ctx context.Context, c confirm.Confirmation) error {
	_, err := s.db.sql.ExecContext(ctx,
		"INSERT INTO confirmations(id,entity_id,action,resource,operator_id,method,reason,scope_hash,ts,expires_at,consumed_at) "+
			"VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
		c.ID, c.EntityID, c.Action, c.Resource, c.OperatorID, c.Method, c.Reason,
		nullStr(c.ScopeHash), c.TS, c.ExpiresAt, c.ConsumedAt)
	return err
}

func (s *ConfirmStore) Get(ctx context.Context, id string) (confirm.Confirmation, error) {
	var (
		c        confirm.Confirmation
		scope    sql.NullString
		consumed sql.NullTime
	)
	err := s.db.sql.QueryRowContext(ctx,
		"SELECT id,entity_id,action,resource,operator_id,method,reason,coalesce(scope_hash,''),ts,expires_at,consumed_at "+
			"FROM confirmations WHERE id=$1", id).
		Scan(&c.ID, &c.EntityID, &c.Action, &c.Resource, &c.OperatorID, &c.Method,
			&c.Reason, &scope, &c.TS, &c.ExpiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return confirm.Confirmation{}, confirm.ErrNotFound
	}
	if err != nil {
		return confirm.Confirmation{}, err
	}
	c.ScopeHash = scope.String
	if consumed.Valid {
		t := consumed.Time
		c.ConsumedAt = &t
	}
	return c, nil
}

func (s *ConfirmStore) Consume(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.sql.ExecContext(ctx,
		"UPDATE confirmations SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL", id, at)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	// 未更新：区分不存在/已消费/已过期，便于上层返回明确错误。
	c, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.ConsumedAt != nil {
		return confirm.ErrConsumed
	}
	if !c.ExpiresAt.After(at) {
		return confirm.ErrExpired
	}
	return confirm.ErrConsumed
}
