// vuln.Store / intel.Store 的 PostgreSQL 实现（005_knowledge.sql / 批四「漏洞情报落 PG」）。
// 幂等口径与库内去重一致：ON CONFLICT DO NOTHING（先到先得，不覆盖既有条目）。
package pgstore

import (
	"database/sql"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

type KBStore struct{ db *DB }

func (d *DB) KB() *KBStore { return &KBStore{d} }

var (
	_ vuln.Store  = (*KBStore)(nil)
	_ intel.Store = (*KBStore)(nil)
)

// ---- 漏洞库 ----

func (s *KBStore) SaveVuln(e vuln.Entry) error {
	_, err := s.db.sql.Exec(`INSERT INTO vuln_entries(cve,title,cvss,epss,severity,category,tags,descr,fix)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (cve) DO NOTHING`,
		e.CVE, e.Title, e.CVSS, e.EPSS, e.Severity, e.Category,
		pq.Array(textArr(e.Tags)), e.Desc, e.Fix)
	return err
}

func (s *KBStore) LoadVulns() ([]vuln.Entry, error) {
	rs, err := s.db.sql.Query(`SELECT cve,title,cvss,epss,severity,category,tags,descr,fix FROM vuln_entries ORDER BY cve`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []vuln.Entry
	for rs.Next() {
		var e vuln.Entry
		var tags pq.StringArray
		if err := rs.Scan(&e.CVE, &e.Title, &e.CVSS, &e.EPSS, &e.Severity, &e.Category, &tags, &e.Desc, &e.Fix); err != nil {
			return nil, err
		}
		e.Tags = []string(tags)
		out = append(out, e)
	}
	return out, rs.Err()
}

// ---- 情报库 ----

func (s *KBStore) SaveIntel(e intel.Entry) error {
	_, err := s.db.sql.Exec(`INSERT INTO intel_entries(key,type,value,threat,family,confidence,source,tags)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (key) DO NOTHING`,
		intel.Key(e), e.Type, e.Value, e.Threat, e.Family, e.Confidence, e.Source,
		pq.Array(textArr(e.Tags)))
	return err
}

func (s *KBStore) LoadIntel() ([]intel.Entry, error) {
	rs, err := s.db.sql.Query(`SELECT type,value,threat,family,confidence,source,tags FROM intel_entries ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []intel.Entry
	for rs.Next() {
		var e intel.Entry
		var fam, src sql.NullString
		var tags pq.StringArray
		if err := rs.Scan(&e.Type, &e.Value, &e.Threat, &fam, &e.Confidence, &src, &tags); err != nil {
			return nil, err
		}
		e.Family, e.Source, e.Tags = nz(fam), nz(src), []string(tags)
		out = append(out, e)
	}
	return out, rs.Err()
}
