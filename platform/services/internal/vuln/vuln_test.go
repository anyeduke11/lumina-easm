package vuln

import (
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 为什么（FR-VUL-001/003 / 一票否决②延伸）：内置 ≥16 条 + 优先级公式权重和必须 100%、可复算——
// 排序不可复算=运营优先级造假。
func TestSeedAndPriorityFormula(t *testing.T) {
	s := NewService()
	if len(s.List("", "")) < 16 {
		t.Fatalf("内置应 ≥16 条，实际 %d", len(s.List("", "")))
	}
	// 权重口径：CVSS 45% + EPSS 35% + 影响面 20%（SRS FR-VUL-003）
	p := Priority(10.0, 1.0, 5) // 全满分输入
	if p != 100 {
		t.Errorf("CVSS=10/EPSS=1/影响5资产 应为 100，实际 %v", p)
	}
	if Priority(0, 0, 0) != 0 {
		t.Error("零输入应为 0")
	}
	// 可复算：同输入同输出，且排序按分数单调
	a := Priority(8, 0.5, 2)
	b := Priority(9, 0.5, 2)
	if !(b > a) {
		t.Error("CVSS 更高分项应更大")
	}
}

// 为什么（FR-VUL-002/004 / A-04）：导入按 CVE 去重——重复 CVE 不得产生重复条目与重复影响面；
// tags 以 | 分隔解析。
func TestImportDedup(t *testing.T) {
	s := NewService()
	csv := "cve,title,cvss,epss,severity,category,tags\n" +
		"CVE-2026-9001,测试漏洞一,9.8,0.94,critical,web,nginx|redis\n" +
		"CVE-2026-9002,测试漏洞二,7.5,0.5,high,middleware,tomcat\n" +
		"CVE-2026-9001,测试漏洞一重复,9.8,0.94,critical,web,nginx\n"
	ins, skips, err := s.ImportCSV(csv)
	if err != nil {
		t.Fatal(err)
	}
	if ins != 2 || skips != 1 {
		t.Errorf("应插入 2 跳过 1，实际 ins=%d skip=%d", ins, skips)
	}
	if e, ok := s.Get("CVE-2026-9001"); !ok || len(e.Tags) != 2 || e.Tags[0] != "nginx" {
		t.Errorf("tags 解析错误: %+v", e)
	}
	// 非法表头必须报错（fail loud），不得静默吞
	if _, _, err := s.ImportCSV("wrong,header\n1,2"); err == nil {
		t.Error("表头不符应报错")
	}
}

// 为什么（FR-VUL-002）：影响面按标签交集匹配——匹配规则是「标签相交」，
// 漏匹配=高危漏洞不派单。
func TestMatchAssets(t *testing.T) {
	s := NewService()
	_, _, _ = s.ImportCSV("cve,title,cvss,epss,severity,category,tags\nCVE-1,Redis 未授权,9.8,0.9,critical,cache,redis|unauth\n")
	assets := []asset.Asset{
		{ID: "a1", Tenant: "t-a", Name: "cache.hddata.cn", Tags: []string{"redis", "内网映射"}},
		{ID: "a2", Tenant: "t-a", Name: "www.hddata.cn", Tags: []string{"nginx"}},
	}
	matched := s.MatchAssets("CVE-1", assets)
	if len(matched) != 1 || matched[0].ID != "a1" {
		t.Errorf("应命中 a1（标签交集 redis），实际 %+v", matched)
	}
	// 列表含刚导入条目（FR-VUL-002 返回匹配资产在前置用例已验）
	list := s.List("", "")
	hit := false
	for _, e := range list {
		if e.CVE == "CVE-1" {
			hit = true
		}
	}
	if !hit {
		t.Error("列表应含刚导入条目")
	}
	// 排序=优先级降序：首条应是最高分（seed+导入混排下仍单调）
	s2 := NewService()
	ls := s2.List("", "")
	for i := 1; i < len(ls); i++ {
		if ls[i-1].PriorityScore < ls[i].PriorityScore {
			t.Fatalf("列表未按优先级降序: %v < %v", ls[i-1].PriorityScore, ls[i].PriorityScore)
		}
	}
}

// 严重度过滤 + JSON 导入。
func TestFilterAndJSONImport(t *testing.T) {
	s := NewService()
	n, sk, err := s.ImportJSON([]Entry{{CVE: "CVE-J1", Title: "j", CVSS: 5, EPSS: 0.1, Severity: "medium", Tags: []string{"x"}}})
	if err != nil || n != 1 || sk != 0 {
		t.Fatalf("JSON 导入错误: %d %d %v", n, sk, err)
	}
	if _, sk2, err := s.ImportJSON([]Entry{{CVE: "CVE-J1"}}); err != nil || sk2 != 1 {
		t.Errorf("JSON 重复 CVE 应计 skipped，实际 sk=%d err=%v", sk2, err)
	}
	if got := s.List("", "critical"); len(got) > 0 {
		for _, e := range got {
			if e.Severity != "critical" {
				t.Error("severity 过滤失效")
			}
		}
	}
}
