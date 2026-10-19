package intel

import (
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 为什么（FR-INT-001）：六类 IOC 合法、其他类型拒绝（口径唯一 C-6）。
func TestTypesGate(t *testing.T) {
	s := NewService()
	if len(s.List("", "")) < 14 {
		t.Fatalf("内置应 ≥14 条，实际 %d", len(s.List("", "")))
	}
	_, _, err := s.ImportJSON([]Entry{{Type: "carrier-pigeon", Value: "x"}})
	if err == nil {
		t.Error("非六类 IOC 应拒绝")
	}
	n, _, err := s.ImportJSON([]Entry{{Type: "domain", Value: "evil.example.org", Threat: "phishing", Confidence: 0.9, Source: "unit"}})
	if err != nil || n != 1 {
		t.Fatalf("合法导入失败: %v %v", err, n)
	}
}

// 为什么（FR-INT-003 / A-04）：按 IOC 值去重——同值重复导入不产生重复情报表项。
func TestImportDedup(t *testing.T) {
	s := NewService()
	csv := "type,value,threat,family,confidence,source\n" +
		"ip,198.51.100.7,scanner,TestFamily,0.95,intel-A\n" +
		"url,http://198.51.100.7/x,scanner,TestFamily,0.8,intel-A\n" +
		"ip,198.51.100.7,scanner-dup,TestFamily,0.9,intel-B\n"
	ins, sk, err := s.ImportCSV(csv)
	if err != nil {
		t.Fatal(err)
	}
	if ins != 2 || sk != 1 {
		t.Errorf("应插入 2 跳过 1，实际 %d %d", ins, sk)
	}
}

// 为什么（FR-INT-002）：命中两规则——「IOC 值/根域出现在资产名」或「标签相交」；
// 漏匹配=失陷资产不被告警。
func TestHitAssets(t *testing.T) {
	s := NewService()
	_, _, _ = s.ImportJSON([]Entry{
		{Type: "domain", Value: "mal-c2.evil.com", Threat: "c2", RootDomain: "evil.com", Confidence: 0.9, Source: "t"},
		{Type: "md5", Value: "d41d8cd98f00b204e9800998ecf8427e", Threat: "webshell", Tags: []string{"webshell"}, Confidence: 0.85, Source: "t"},
	})
	assets := []asset.Asset{
		{ID: "h1", Name: "vpn.evil.com", Tags: []string{"vpn"}},                // 根域命中
		{ID: "h2", Name: "www.hddata.cn", Tags: []string{"webshell", "nginx"}}, // 标签命中
		{ID: "h3", Name: "evilcompany.cn", Tags: []string{"corp"}},             // 子串≠域命中：evil.com 不是 evilcompany.cn 的根域
	}
	hits := s.HitAssets(assets)
	got := map[string][]string{}
	for _, h := range hits {
		got[h.AssetID] = append(got[h.AssetID], h.IOC.Value)
	}
	if len(got["h1"]) == 0 || got["h1"][0] != "mal-c2.evil.com" {
		t.Errorf("h1 应根域命中: %+v", got)
	}
	if len(got["h2"]) == 0 {
		t.Errorf("h2 应标签命中: %+v", got)
	}
	if _, bad := got["h3"]; bad {
		t.Errorf("h3 不应命中（evilcompany.cn 根域≠evil.com）: %+v", got)
	}
}

// 根域提取：IP 无根域；多级公共后缀从简（取末两段）——错误根域导致整片误命中。
func TestRootDomain(t *testing.T) {
	cases := map[string]string{"a.evil.com": "evil.com", "evil.com": "evil.com", "deep.sub.hddata.cn": "hddata.cn", "": ""}
	for in, want := range cases {
		if got := RootDomain(in); got != want {
			t.Errorf("RootDomain(%q)=%q want %q", in, got, want)
		}
	}
}
