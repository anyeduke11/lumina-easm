package intel

import (
	"errors"
	"testing"
)

// 为什么（005_knowledge.sql）：情报条目与漏洞库同理必须跨重启留存；
// 去重键必须与内存一致（type|lower(value)），否则 DB 与内存两套去重口径 = C-6 违例。
type fakeIntelStore struct {
	saved     map[string]Entry
	preload   []Entry
	failOnVal string
}

func (f *fakeIntelStore) SaveIntel(e Entry) error {
	if e.Value == f.failOnVal {
		return errors.New("db down")
	}
	f.saved[Key(e)] = e
	return nil
}

func (f *fakeIntelStore) LoadIntel() ([]Entry, error) { return f.preload, nil }

func TestIntelAttachStorePersistsSeedAndHydrates(t *testing.T) {
	f := &fakeIntelStore{saved: map[string]Entry{}, preload: []Entry{
		{Type: "domain", Value: "ext-c2.example.net", Threat: "c2", Confidence: 0.9, Source: "feed"},
	}}
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	if len(f.saved) < 15 {
		t.Errorf("seed 应全部写穿，实际 %d", len(f.saved))
	}
	got := s.List("domain", "")
	found := false
	for _, e := range got {
		if e.Value == "ext-c2.example.net" {
			found = true
		}
	}
	if !found {
		t.Error("DB 真源条目应 hydrate 回内存")
	}
}

func TestIntelImportWritesThroughAndKeyConsistent(t *testing.T) {
	f := &fakeIntelStore{saved: map[string]Entry{}}
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	n, _, err := s.ImportCSV("type,value,threat,family,confidence,source\nip,198.51.100.99,scan,,0.9,feed\n")
	if err != nil || n != 1 {
		t.Fatalf("导入失败: %v %v", n, err)
	}
	if _, ok := f.saved["ip|198.51.100.99"]; !ok {
		t.Errorf("写穿 key 必须为 type|lower(value)，实际 %v", f.saved)
	}
}

func TestIntelImportStoreFailureNoGhost(t *testing.T) {
	f := &fakeIntelStore{saved: map[string]Entry{}, failOnVal: "198.51.100.98"}
	s := NewService()
	if err := s.AttachStore(f); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ImportCSV("type,value,threat,family,confidence,source\nip,198.51.100.98,scan,,0.9,feed\n"); err == nil {
		t.Fatal("持久层故障应报错")
	}
	for _, e := range s.List("ip", "") {
		if e.Value == "198.51.100.98" {
			t.Fatal("写穿失败不得留下内存幽灵条目")
		}
	}
}

// Key 与 put/Import 的去重口径一致（域段大小写折叠）。
func TestKeyLowerFolds(t *testing.T) {
	if Key(Entry{Type: "domain", Value: "Evil-C2.Example.NET"}) != "domain|evil-c2.example.net" {
		t.Error("key 口径错误")
	}
}
