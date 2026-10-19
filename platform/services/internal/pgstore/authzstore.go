// authz.Store 的 PostgreSQL 实现（007_authz.sql；整 Scope JSONB 存储）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
)

type AuthzStore struct{ db *DB }

func (d *DB) Authz() *AuthzStore { return &AuthzStore{d} }

var _ authz.Store = (*AuthzStore)(nil)

func (s *AuthzStore) Put(ctx context.Context, sc authz.Scope) error {
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO auth_scopes(tenant_id,scope) VALUES($1,$2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET scope=EXCLUDED.scope, updated_at=now()`, sc.Tenant, b)
	return err
}

func (s *AuthzStore) Get(ctx context.Context, tenant string) (authz.Scope, bool, error) {
	var b []byte
	err := s.db.sql.QueryRowContext(ctx, `SELECT scope FROM auth_scopes WHERE tenant_id=$1`, tenant).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.Scope{}, false, nil
	}
	if err != nil {
		return authz.Scope{}, false, err
	}
	var sc authz.Scope
	if err := json.Unmarshal(b, &sc); err != nil {
		return authz.Scope{}, false, err
	}
	return sc, true, nil
}
