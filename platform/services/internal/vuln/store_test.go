package vuln

import (
	"errors"
	"testing"
)

// 为什么（005_knowledge.sql / 批三遗留「重启即失」销账）：导入条目必须写穿持久层，
// 且 Attach 后以 DB 为真源 hydrate——否则重启丢数据仍对外宣称「库内 N 条」= 造假。
type fakeVulnStore struct {
	saved     map[string]Entry
	preload   []Entry
	loadErr   error
	failOnCVE string
}

func (f *fakeVulnStore) SaveVuln(e Entry) error {
	if e.CVE == f.failOnCVE {
		return errors.New("db down")
	}
	f.saved[e.CVE] = e
	return nil
}

func (f *fakeVulnStore) LoadVulns() ([]Entry, error) { return f.preload, f.loadErr }

func newFake() *fakeVulnStore {
	return &fakeVulnStore{saved: map[string]Entry{}}
}

func TestAttachStorePersistsSeedAndHydrates(t *testing.T) {
	f := newFake()
	f.preload = []Entry{{CVE: "CVE-2020-0001", Title: "重启前导入的外部条目", CVSS: 5.0, Severity: "medium", Tags: []string{"x"}}}
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	if len(f.saved) < 18 {
		t.Errorf("seed 应全部写穿入库，实际 %d", len(f.saved))
	}
	if _, ok := s.Get("CVE-2020-0001"); !ok {
		t.Error("DB 真源条目应 hydrate 回内存（跨重启不丢）")
	}
}

func TestImportWritesThroughStore(t *testing.T) {
	f := newFake()
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	n, _, err := s.ImportCSV("cve,title,cvss,epss,severity,category,tags\nCVE-2026-99001,新洞,9.0,0.5,high,c,redis\nCVE-2026-20201,重复,9.8,0.94,critical,cache,redis\n")
	if err != nil || n != 1 {
		t.Fatalf("导入应 inserted=1: %v %v", n, err)
	}
	if _, ok := f.saved["CVE-2026-99001"]; !ok {
		t.Error("新条目必须落持久层")
	}
}

// 写穿失败必须 fail loud 且内存不留「未入库的幽灵条目」（否则界面计数与 DB 分叉）。
func TestImportStoreFailureNoGhostEntry(t *testing.T) {
	f := newFake()
	f.failOnCVE = "CVE-2026-99002"
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.ImportCSV("cve,title,cvss,epss,severity,category,tags\nCVE-2026-99002,x,9.0,0.5,high,c,redis\n")
	if err == nil {
		t.Fatal("持久层故障应报错")
	}
	if _, ok := s.Get("CVE-2026-99002"); ok {
		t.Error("写穿失败的条目不得进入内存（防分叉）")
	}
}
