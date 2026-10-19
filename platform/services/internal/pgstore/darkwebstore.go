// 010_darkweb.sql 的 PostgreSQL 实现：ownership.FPStore（指纹基线整包 JSONB）+
// darkweb.Store（线索包，WORM 首次=ON CONFLICT DO NOTHING——重放不改写已出通报材料）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

type DarkwebStore struct{ db *DB }

func (d *DB) Darkweb() *DarkwebStore { return &DarkwebStore{d} }

var (
	_ ownership.FPStore = (*DarkwebStore)(nil)
	_ darkweb.Store     = (*DarkwebStore)(nil)
)

// ---- ownership.FPStore ----

func (s *DarkwebStore) List(ctx context.Context) (map[string]ownership.Fingerprints, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT tenant_id, fp FROM ownership_fingerprints`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string]ownership.Fingerprints{}
	for rs.Next() {
		var (
			tid string
			b   []byte
		)
		if err := rs.Scan(&tid, &b); err != nil {
			return nil, err
		}
		var fp ownership.Fingerprints
		if err := json.Unmarshal(b, &fp); err != nil {
			return nil, err
		}
		out[tid] = fp
	}
	return out, rs.Err()
}

func (s *DarkwebStore) Save(ctx context.Context, tenantID string, fp ownership.Fingerprints) error {
	b, err := json.Marshal(fp)
	if err != nil {
		return err
	}
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO ownership_fingerprints(tenant_id,fp) VALUES($1,$2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET fp=EXCLUDED.fp, updated_at=now()`, tenantID, b)
	return err
}

// ---- darkweb.Store ----

func (s *DarkwebStore) SavePackage(ctx context.Context, pkg darkweb.LeadPackage) error {
	b, err := json.Marshal(pkg)
	if err != nil {
		return err
	}
	// WORM 首次：同 package_id 重复=保留首份（与证据对象 ErrImmutable 同口径；
	// content_hash 入唯一键位——同 ID 异内容不可能发生，出现即数据异常，故只按 ID 挡）
	_, err = s.db.sql.ExecContext(ctx, `INSERT INTO lead_packages
(package_id,tenant_id,content_hash,evidence_ref,pkg,generated_at)
VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT (package_id) DO NOTHING`,
		pkg.PackageID, pkg.TenantID, pkg.ContentHash, pkg.EvidenceRef, b, pkg.GeneratedAt)
	return err
}

func (s *DarkwebStore) ListPackages(ctx context.Context, tenantID string) ([]darkweb.LeadPackage, error) {
	rs, err := s.db.sql.QueryContext(ctx, `SELECT pkg FROM lead_packages WHERE tenant_id=$1 ORDER BY created_at, package_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []darkweb.LeadPackage
	for rs.Next() {
		var b []byte
		if err := rs.Scan(&b); err != nil {
			return nil, err
		}
		var p darkweb.LeadPackage
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rs.Err()
}

func (s *DarkwebStore) GetPackage(ctx context.Context, tenantID, packageID string) (darkweb.LeadPackage, bool, error) {
	var b []byte
	err := s.db.sql.QueryRowContext(ctx, `SELECT pkg FROM lead_packages WHERE tenant_id=$1 AND package_id=$2`, tenantID, packageID).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) { // 租户不匹配与不存在同响应=不泄露他租户包存在性（AX-5 口径）
		return darkweb.LeadPackage{}, false, nil
	}
	if err != nil {
		return darkweb.LeadPackage{}, false, err
	}
	var p darkweb.LeadPackage
	if err := json.Unmarshal(b, &p); err != nil {
		return darkweb.LeadPackage{}, false, err
	}
	return p, true, nil
}
