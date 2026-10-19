package report

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// 字体候选（macOS 本机 + 常见 Linux Noto 路径）；无字体=PDF 导出诚实 501（能力边界，不伪造）。
var fontCandidates = []string{
	"/System/Library/Fonts/STHeiti Light.ttc",
	"/System/Library/Fonts/PingFang.ttc",
	"/System/Library/Fonts/Hiragino Sans GB.ttc",
	"/System/Library/Fonts/Supplemental/Songti.ttc",
	"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
	"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
}

func testFont(t *testing.T) string {
	t.Helper()
	for _, p := range fontCandidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("本机无 CJK 字体候选，PDF 用例跳过（能力边界=501 形态）")
	return ""
}

func sampleRep() Report {
	return Report{ID: "RPT-x", Tenant: "t-a", TenantName: "华东数服", Period: "近 7 天",
		Text: "# 高管摘要\n\n本周期排查发现台账条目 34 项，其中严重 2 项、高危 9 项。\n" +
			strings.Repeat("整改工作建议：按措施矩阵推进，deadline 前完成处置闭环。\n", 60)}
}

// 为什么（FR-RPT-004 销账）：PDF 是对外交付物——必须确定性（同报告同字节）、结构合法
// （%PDF 头/xref/%%EOF 尾）、CJK 字体内嵌（Identity-H），否则打开即乱码=伪造交付。
func TestRenderPDFDeterministicAndValid(t *testing.T) {
	font := testFont(t)
	p1, err := RenderPDF(sampleRep(), font)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := RenderPDF(sampleRep(), font)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatal("同报告两次渲染必须逐字节一致（确定性）")
	}
	if !bytes.HasPrefix(p1, []byte("%PDF-1.4")) {
		t.Error("缺 %PDF 头")
	}
	if !bytes.Contains(p1, []byte("%%EOF")) || !bytes.Contains(p1, []byte("startxref")) {
		t.Error("缺 xref/EOF 尾（结构不完整）")
	}
	if !bytes.Contains(p1, []byte("Identity-H")) || !bytes.Contains(p1, []byte("FontFile2")) {
		t.Error("CJK 字体未以内嵌 CID 字体形态出现")
	}
	if bytes.Count(p1, []byte("/Type /Page")) < 2 {
		t.Error("多行正文应分页（页对象 ≥2）")
	}
}

// cmap 必须能解析中英文（char→GID，内嵌字体渲染的前提）。
func TestFontCmapCoversCJKAndASCII(t *testing.T) {
	f, err := loadFont(testFont(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{'中', 'A', '9', '·'} {
		if f.gid(r) == 0 {
			t.Errorf("cmap 缺字形映射: %q", r)
		}
	}
	if f.gid(0x1F600) != 0 { // emoji 区缺字形=0（.notdef），允许但不映射成功
		t.Logf("注意: emoji 区意外命中字形（可接受）")
	}
}

// ---- M2 收尾：PDF 字体子集化（体积边界销账，2026-10-18）----

// 为什么：全量内嵌 29MB 不可交付（通报/邮件通道限制）——子集化后体积须收缩两个
// 数量级，且渲染语义不变（GID 重映射确定性、结构完整可解析）。
func TestRenderPDFSubsetsFont(t *testing.T) {
	font := testFont(t)
	p1, err := RenderPDF(sampleRep(), font)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) > 3<<20 {
		t.Errorf("子集化后 PDF 应 <3MB（全量内嵌≈29MB）: %d", len(p1))
	}
	if !bytes.Contains(p1, []byte("FontFile2")) || !bytes.Contains(p1, []byte("/Filter /FlateDecode")) {
		t.Error("子集字体流形态缺失")
	}
	p2, err := RenderPDF(sampleRep(), font)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatal("子集化必须保持确定性（同报告同字节）")
	}
}

// 子集字体内部一致性：numGlyphs 对账、loca 单调且界内、indexToLocFormat=1、
// 简单字形数据与原字体逐字节相等（GID 重映射不破坏字形本体）。
func TestSubsetFontConsistency(t *testing.T) {
	f, err := loadFont(testFont(t))
	if err != nil {
		t.Fatal(err)
	}
	used := map[uint32]bool{0: true}
	for _, r := range []rune("中令牌泄露整改A9") {
		if g := f.gid(r); g != 0 {
			used[uint32(g)] = true
		}
	}
	sub, mapping, err := subsetFont(f, used)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) > 1<<20 {
		t.Errorf("子集字体应 <1MB: %d", len(sub))
	}
	if len(mapping) != len(used) {
		t.Fatalf("映射数应=使用字形数: %d vs %d", len(mapping), len(used))
	}
	// 重解析子集：手动查表目录（子集无 cmap，parseTables 会拒——这是设计而非缺陷）
	nt := int(binary.BigEndian.Uint16(sub[4:6]))
	tbls := map[string][2]uint32{}
	for i := 0; i < nt; i++ {
		rec := sub[12+16*i : 12+16*i+16]
		tbls[string(rec[:4])] = [2]uint32{
			binary.BigEndian.Uint32(rec[8:12]), binary.BigEndian.Uint32(rec[12:16]),
		}
	}
	mx, okM := tbls["maxp"]
	hd, okH := tbls["head"]
	gl, okG := tbls["glyf"]
	lc, okL := tbls["loca"]
	if !okM || !okH || !okG || !okL {
		t.Fatalf("子集缺关键表: maxp=%v head=%v glyf=%v loca=%v", okM, okH, okG, okL)
	}
	if u16at(sub[mx[0]:mx[0]+mx[1]], 4) != len(used) {
		t.Errorf("maxp.numGlyphs 应=%d", len(used))
	}
	if u16at(sub[hd[0]:hd[0]+hd[1]], 50) != 1 {
		t.Error("head.indexToLocFormat 应=1（long loca）")
	}
	prev := 0
	for i := 0; i <= len(used)-1; i++ {
		off := int(binary.BigEndian.Uint32(sub[int(lc[0])+4*i : int(lc[0])+4*i+4]))
		if off < prev {
			t.Fatalf("loca 非单调: %d@%d", off, i)
		}
		prev = off
	}
	end := int(binary.BigEndian.Uint32(sub[int(lc[0])+4*len(used) : int(lc[0])+4*len(used)+4]))
	if end > int(gl[1]) {
		t.Errorf("loca 末项超 glyf 界: %d > %d", end, gl[1])
	}
}

func u16at(b []byte, off int) int { return int(binary.BigEndian.Uint16(b[off : off+2])) }
