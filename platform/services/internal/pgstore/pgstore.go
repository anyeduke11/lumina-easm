// Package pgstore 用 PostgreSQL 实现 tenant.Store 与 asset.Store（WP-M0-03/04）。
//
// RLS 纵深防御模型（001_init.sql，策略为 NULL=穿透）：
//   - ListByTenant / Create 在事务内 set_config('easm.tenant_id',…)：
//     即使查询拼错 WHERE，数据库层也保证行过滤 / 异租户插入被拒（FR-TEN-005）。
//   - Get 不设置 GUC（平台穿透模式）：跨租户行可读，由 Service 层判 InScope
//     返回 403 + deny 审计——与内存后端保持同一 API 契约（一致性 C-6）。
package pgstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

type DB struct{ sql *sql.DB }

// Open 建立连接池；dsn 应指向 easm_app 角色（无 SUPERUSER/BYPASSRLS，RLS 生效）。
func Open(dsn string) (*DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &DB{sql: db}, nil
}

func (d *DB) Tenants() *TenantStore { return &TenantStore{d} }
func (d *DB) Assets() *AssetStore   { return &AssetStore{d} }

// withTenant 在事务内设置 RLS GUC。
func (d *DB) withTenant(ctx context.Context, tenantID string, fn func(tx *sql.Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('easm.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func textArr(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func isDup(err error) bool {
	var pe *pq.Error
	return errors.As(err, &pe) && pe.Code == "23505"
}

func isRLSDeny(err error) bool {
	var pe *pq.Error
	return errors.As(err, &pe) && pe.Code == "42501"
}

// ---- TenantStore 实现 tenant.Store ----

type TenantStore struct{ db *DB }

func (s *TenantStore) Create(_ context.Context, t tenant.Tenant) error {
	_, err := s.db.sql.Exec(`INSERT INTO tenants
(id,name,short,industry,level,plan,root_domains,cidrs,contact,region,theme_color,status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		t.ID, t.Name, t.Short, t.Industry, t.Level, t.Plan,
		pq.Array(textArr(t.RootDomains)), pq.Array(textArr(t.CIDRs)),
		t.Contact, t.Region, t.ThemeColor, t.Status)
	if isDup(err) {
		return tenant.ErrDuplicate
	}
	return err
}

const tenantCols = `id,name,short,industry,level,plan,root_domains,cidrs,contact,region,theme_color,status,contract_end`

func scanTenant(row interface{ Scan(dest ...any) error }) (tenant.Tenant, error) {
	var (
		t                                             tenant.Tenant
		short, ind, lvl, plan, contact, region, theme sql.NullString
		ce                                            sql.NullTime
		rd, cidr                                      pq.StringArray
	)
	err := row.Scan(&t.ID, &t.Name, &short, &ind, &lvl, &plan,
		&rd, &cidr,
		&contact, &region, &theme, &t.Status, &ce)
	t.RootDomains, t.CIDRs = []string(rd), []string(cidr)
	t.Short, t.Industry, t.Level, t.Plan = nz(short), nz(ind), nz(lvl), nz(plan)
	t.Contact, t.Region, t.ThemeColor = nz(contact), nz(region), nz(theme)
	if ce.Valid {
		t.ContractEnd = ce.Time
	}
	return t, err
}

func (s *TenantStore) Get(ctx context.Context, id string) (tenant.Tenant, error) {
	row := s.db.sql.QueryRowContext(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id=$1`, id)
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.Tenant{}, tenant.ErrNotFound
	}
	return t, err
}

func (s *TenantStore) List(ctx context.Context) ([]tenant.Tenant, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []tenant.Tenant
	for rs.Next() {
		t, err := scanTenant(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rs.Err()
}

// ---- AssetStore 实现 asset.Store ----

type AssetStore struct{ db *DB }

const assetCols = `id,tenant_id,name,type,type_label,ip,risk,exp,owner,found,status,beian,source,biz,tags,ai,ports,tech`

func scanAsset(row interface{ Scan(dest ...any) error }) (asset.Asset, error) {
	var (
		a          asset.Asset
		tl, ip, ai sql.NullString
		tags, tech pq.StringArray
		portsArr   pq.Int64Array
	)
	err := row.Scan(&a.ID, &a.Tenant, &a.Name, &a.Type, &tl, &ip, &a.Risk, &a.Exp,
		&a.Owner, &a.Found, &a.Status, &a.Beian, &a.Source, &a.Biz,
		&tags, &ai, &portsArr, &tech)
	a.TypeLabel, a.IP, a.AI = nz(tl), nz(ip), nz(ai)
	a.Tags, a.Tech = []string(tags), []string(tech)
	a.Ports = intsFrom(portsArr)
	return a, err
}

func (s *AssetStore) Create(ctx context.Context, a asset.Asset) error {
	err := s.db.withTenant(ctx, a.Tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO assets
(id,tenant_id,name,type,type_label,ip,risk,exp,owner,found,status,beian,source,biz,tags,ai,ports,tech)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			a.ID, a.Tenant, a.Name, a.Type, a.TypeLabel, a.IP, a.Risk, a.Exp, a.Owner,
			a.Found, a.Status, a.Beian, a.Source, a.Biz,
			pq.Array(textArr(a.Tags)), a.AI, pq.Array(intSlice(a.Ports)), pq.Array(textArr(a.Tech)))
		return err
	})
	switch {
	case err == nil:
		return nil
	case isDup(err):
		return asset.ErrDuplicate
	case isRLSDeny(err): // WITH CHECK：异租户插入在 DB 层被拒
		return asset.ErrInvalid
	default:
		return err
	}
}

func (s *AssetStore) Get(ctx context.Context, id string) (asset.Asset, error) {
	// 显式穿透事务（GUC=''）：不依赖连接上可能残留的会话值；
	// 行可读后由 Service 层判 InScope，越权返回 403+deny 审计（与内存后端同一契约）。
	var a asset.Asset
	err := s.db.withTenant(ctx, "", func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT `+assetCols+` FROM assets WHERE id=$1`, id)
		var err error
		a, err = scanAsset(row)
		if errors.Is(err, sql.ErrNoRows) {
			return asset.ErrNotFound
		}
		return err
	})
	return a, err
}

// Delete 供入账补偿回滚（asset.Service 投影失败时调用）。
func (s *AssetStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.sql.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, id)
	return err
}

func (s *AssetStore) ListByTenant(ctx context.Context, tenantID string) ([]asset.Asset, error) {
	var out []asset.Asset
	err := s.db.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		rs, err := tx.Query(`SELECT `+assetCols+` FROM assets WHERE tenant_id=$1 ORDER BY id`, tenantID)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			a, err := scanAsset(rs)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rs.Err()
	})
	return out, err
}

func intSlice(is []int) []int64 {
	out := make([]int64, 0, len(is))
	for _, i := range is {
		out = append(out, int64(i))
	}
	return out
}

func intsFrom(i64 []int64) []int {
	out := make([]int, 0, len(i64))
	for _, i := range i64 {
		out = append(out, int(i))
	}
	return out
}

func nz(s sql.NullString) string {
	if s.Valid {
		return s.String
	}
	return ""
}

var (
	_ tenant.Store = (*TenantStore)(nil)
	_ asset.Store  = (*AssetStore)(nil)
)
