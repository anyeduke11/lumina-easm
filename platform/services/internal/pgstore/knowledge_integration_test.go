package pgstore

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

// 为什么（005 / 批四）：验证「跨重启不丢」与「先到先得」两条承诺在真实 PG 上成立；
// 用 ITEST 前缀数据并全程清理，不污染共享库。
func kbDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成测试")
	}
	raw, err := sql.Open("postgres", dsn)
	if err == nil {
		_, _ = raw.Exec(`DELETE FROM vuln_entries WHERE cve LIKE 'CVE-ITEST%'`)
		_, _ = raw.Exec(`DELETE FROM intel_entries WHERE value LIKE '%itest.example%'`)
		raw.Close()
	}
	t.Cleanup(func() {
		if c, err := sql.Open("postgres", dsn); err == nil {
			_, _ = c.Exec(`DELETE FROM vuln_entries WHERE cve LIKE 'CVE-ITEST%'`)
			_, _ = c.Exec(`DELETE FROM intel_entries WHERE value LIKE '%itest.example%'`)
			c.Close()
		}
	})
	return dsn
}

func TestKBVulnUpsertFirstWins(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	kb := db.KB()
	if err := kb.SaveVuln(vuln.Entry{CVE: "CVE-ITEST-0001", Title: "先入账", CVSS: 9.0, Tags: []string{"redis"}}); err != nil {
		t.Fatal(err)
	}
	if err := kb.SaveVuln(vuln.Entry{CVE: "CVE-ITEST-0001", Title: "后到覆盖？", CVSS: 1.0}); err != nil {
		t.Fatal(err)
	}
	rows, err := kb.LoadVulns()
	if err != nil {
		t.Fatal(err)
	}
	var found *vuln.Entry
	for i := range rows {
		if rows[i].CVE == "CVE-ITEST-0001" {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatal("ITEST 条目应可回读")
	}
	if found.Title != "先入账" || found.CVSS != 9.0 || len(found.Tags) != 1 || found.Tags[0] != "redis" {
		t.Errorf("先到先得语义被破坏: %+v", *found)
	}
}

// 模拟重启：service1 导入 → service2 Attach 后必须仍在（批三遗留销账主断言）。
func TestKBRestartRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	s1 := vuln.NewService()
	if err := s1.AttachStore(db.KB()); err != nil {
		t.Fatal(err)
	}
	n, _, err := s1.ImportJSON([]vuln.Entry{{CVE: "CVE-ITEST-0002", Title: "重启前导入", CVSS: 7.5, Severity: "high", Tags: []string{"nginx"}}})
	if err != nil || n != 1 {
		t.Fatalf("导入失败: %v %v", n, err)
	}
	s2 := vuln.NewService() // 「重启」
	if err := s2.AttachStore(db.KB()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("CVE-ITEST-0002"); !ok {
		t.Error("跨重启丢失导入条目")
	}
}

func TestKBIntelRoundTrip(t *testing.T) {
	db, err := Open(kbDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	s1 := intel.NewService()
	if err := s1.AttachStore(db.KB()); err != nil {
		t.Fatal(err)
	}
	n, _, err := s1.ImportJSON([]intel.Entry{{Type: "domain", Value: "c2-itest.example", Threat: "c2", Confidence: 0.9, Source: "itest"}})
	if err != nil || n != 1 {
		t.Fatalf("导入失败: %v %v", n, err)
	}
	s2 := intel.NewService()
	if err := s2.AttachStore(db.KB()); err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, e := range s2.List("domain", "") {
		if e.Value == "c2-itest.example" {
			hit = true
			if e.RootDomain != "c2-itest.example" { // 派生字段必须在 hydrate 时重建
				t.Errorf("root_domain 未重建: %+v", e)
			}
		}
	}
	if !hit {
		t.Error("情报条目跨重启丢失")
	}
}
