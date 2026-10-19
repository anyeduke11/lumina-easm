// 最小确定性 PDF writer（FR-RPT-004 销账「PDF 遗留」；IR-07 报告面；M2-09；AX-3 C-5）——
// 零第三方依赖、确定性输出、CJK 内嵌（Type0/Identity-H/FontFile2）。
package report

// 设计约束（本地化 §14：零第三方依赖）：
//
// 编号：FR-RPT-004 / IR-07 报告面 / AX-3 C-5。
// 设计约束（本地化 §14：零第三方依赖）：
//   - Type0 + Identity-H + 内嵌 TrueType（FontFile2）：CJK 正确显示的前提；
//   - 不做字形子集化（GID=原字体 GID，cmap 直查 char→GID）——字体文件较大但实现面最小；
//   - DW=1000（默认字宽）：CJK 等宽近似成立，拉丁字符略宽（可读，不损失信息）；
//   - 无时间戳/无随机 ID：同报告两次渲染逐字节一致（AX-3 可独立复核）；
//   - 字体找不到=显式报错（HTTP 侧 501 pdf_font_unavailable），不伪造 PDF。
// 布局：A4 纵向，56pt 边距，正文 10.5pt、行高 15pt，按字符数换行（等宽近似下的安全口径）。

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

// FindCJKFont 按候选序找第一个存在的 CJK 字体（ttc/ttf）；无则返回 ""（HTTP 侧 501 诚实边界）。
// STHeiti 优先：FontFile2 仅支持 TrueType 轮廓（OTTO/CFF 集合须跳过，见 loadFont）。
func FindCJKFont() string {
	for _, p := range []string{
		"/System/Library/Fonts/STHeiti Light.ttc",
		"/System/Library/Fonts/PingFang.ttc",
		"/System/Library/Fonts/Hiragino Sans GB.ttc",
		"/System/Library/Fonts/Supplemental/Songti.ttc",
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// pdfFont 内嵌字体所需的最小解析面：cmap（char→GID 惰性二分，不物化全表——
// CJK 字体常含跨数万码位的巨型分组，物化会爆内存/耗时）+ 度量表。
// raw=整个字体文件；dir=本字体的表目录基准（TTC 内各字体共享文件级偏移——
// OpenType 规范：TTC 的表偏移相对 **TTC 文件头**，实测 Apple 字体亦如此）。
type pdfFont struct {
	raw      []byte
	dir      int
	baseName string
	upem     int
	ascent   int
	descent  int
	bbox     [4]int
	groups   [][3]uint32 // format12：{startChar, endChar, startGID}（升序不重叠）
	cmap4    []byte      // format4 原始子表（nil=无）
	cmap4Seg int
	tables   map[string]sfntTable // 表目录缓存（parseTables 产出，子集化复用）
	newGID   map[uint32]uint16    // 子集 GID 重映射（subsetFont 产出；nil=直用原 GID）
}

// loadFont 解析 ttc 或 ttf。ttc 集合内逐字体找第一个 **TrueType 轮廓**（sfnt 版本
// 0x00010000/'true'）——FontFile2 只支持 glyf 轮廓；OTTO/CFF（如 Hiragino）跳过不冒充。
func loadFont(path string) (*pdfFont, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pdf: 字体读取失败: %w", err)
	}
	base := strings.TrimSuffix(strings.TrimSuffix(path, ".ttc"), ".ttf")
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	offsets := []uint32{0}
	if len(raw) > 12 && string(raw[:4]) == "ttcf" {
		n := int(binary.BigEndian.Uint32(raw[8:12]))
		if n <= 0 || n > 64 {
			return nil, fmt.Errorf("pdf: ttc 字体数异常: %d", n)
		}
		offsets = offsets[:0]
		for i := 0; i < n; i++ {
			offsets = append(offsets, binary.BigEndian.Uint32(raw[12+4*i:16+4*i]))
		}
	}
	var lastErr error
	for _, off := range offsets {
		if int(off)+12 > len(raw) || off+4 > uint32(len(raw)) {
			continue
		}
		ver := binary.BigEndian.Uint32(raw[off : off+4])
		if ver != 0x00010000 && ver != 0x74727565 { // 0x00010000 / 'true'；OTTO=CFF 跳过
			lastErr = fmt.Errorf("pdf: 集合内字体 %d 非 TrueType 轮廓（ver=%#x），跳过", off, ver)
			continue
		}
		f := &pdfFont{raw: raw, dir: int(off), baseName: base}
		if err := f.parseTables(); err != nil {
			lastErr = err
			continue
		}
		return f, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("pdf: 字体文件为空")
	}
	return nil, lastErr
}

type sfntTable struct{ off, length uint32 }

func (f *pdfFont) parseTables() error {
	if len(f.raw) < f.dir+12 {
		return fmt.Errorf("pdf: 字体过短")
	}
	numTables := int(binary.BigEndian.Uint16(f.raw[f.dir+4 : f.dir+6]))
	tables := map[string]sfntTable{}
	for i := 0; i < numTables; i++ {
		rec := f.raw[f.dir+12+16*i : f.dir+12+16*i+16]
		tables[string(rec[:4])] = sfntTable{
			off:    binary.BigEndian.Uint32(rec[8:12]),
			length: binary.BigEndian.Uint32(rec[12:16]),
		}
	}
	f.tables = tables
	head, ok := tables["head"]
	if !ok {
		return fmt.Errorf("pdf: 字体缺 head 表")
	}
	u16 := func(b []byte, off int) int { return int(binary.BigEndian.Uint16(b[off : off+2])) }
	i16 := func(b []byte, off int) int { return int(int16(binary.BigEndian.Uint16(b[off : off+2]))) }
	hb := f.raw[head.off : head.off+head.length]
	f.upem = u16(hb, 18)
	f.bbox = [4]int{i16(hb, 36), i16(hb, 38), i16(hb, 40), i16(hb, 42)}
	if hh, ok := tables["hhea"]; ok {
		h := f.raw[hh.off : hh.off+hh.length]
		f.ascent, f.descent = i16(h, 4), i16(h, 6)
	}
	cm, ok := tables["cmap"]
	if !ok {
		return fmt.Errorf("pdf: 字体缺 cmap 表")
	}
	return f.parseCmap(f.raw[cm.off : cm.off+cm.length])
}

// parseCmap 选最优子表（3,10 format12 > 任意 format12 > 3,1 format4 > 0,x format4 > 其余 format4）。
func (f *pdfFont) parseCmap(cm []byte) error {
	num := int(binary.BigEndian.Uint16(cm[2:4])) // cmap 头=version(2)+numTables(2)，记录自 4 起
	best, bestScore := -1, -1
	for i := 0; i < num; i++ {
		rec := cm[4+8*i : 4+8*i+8]
		pid, eid := int(binary.BigEndian.Uint16(rec[0:2])), int(binary.BigEndian.Uint16(rec[2:4]))
		off := int(binary.BigEndian.Uint32(rec[4:8]))
		if off+2 > len(cm) {
			continue
		}
		format := int(binary.BigEndian.Uint16(cm[off : off+2]))
		score := -1
		switch {
		case format == 12 && pid == 3 && eid == 10:
			score = 5
		case format == 12:
			score = 4
		case format == 4 && pid == 3 && eid == 1:
			score = 3
		case format == 4 && pid == 0:
			score = 2
		case format == 4:
			score = 1
		}
		if score > bestScore {
			best, bestScore = off, score
		}
	}
	if best < 0 || bestScore < 0 {
		return fmt.Errorf("pdf: cmap 无 format4/12 子表")
	}
	sub := cm[best:]
	if int(binary.BigEndian.Uint16(sub[0:2])) == 12 {
		return f.parseCmap12(sub)
	}
	return f.parseCmap4(sub)
}

func (f *pdfFont) parseCmap12(sub []byte) error {
	n := int(binary.BigEndian.Uint32(sub[12:16]))
	if n > 1<<20 {
		return fmt.Errorf("pdf: format12 分组数异常: %d", n)
	}
	f.groups = make([][3]uint32, 0, n)
	for i := 0; i < n; i++ {
		g := sub[16+12*i : 16+12*i+12]
		f.groups = append(f.groups, [3]uint32{
			binary.BigEndian.Uint32(g[0:4]),
			binary.BigEndian.Uint32(g[4:8]),
			binary.BigEndian.Uint32(g[8:12]),
		})
	}
	return nil
}

func (f *pdfFont) parseCmap4(sub []byte) error {
	seg := int(binary.BigEndian.Uint16(sub[6:8])) / 2
	f.cmap4, f.cmap4Seg = sub, seg
	return nil
}

// gid char→GID 惰性查找（format12 二分优先；format4 分段二分）。缺字形=0（.notdef）。
// fontStream FontFile2 流体：FlateDecode 压缩（全量 CJK 字体 ~20MB → 压缩可至数 MB；
// flate 固定压缩级别=确定性输出；查看器透明解压）。
func fontStream(raw []byte) string {
	var z bytes.Buffer
	zw, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return fmt.Sprintf("<< /Length %d /Filter /FlateDecode /Length1 %d >>\nstream\n%s\nendstream", z.Len(), len(raw), z.String())
}

// gid char→GID（子集化后经 newGID 重映射；缺字形=0=.notdef）。
func (f *pdfFont) gid(r rune) uint16 {
	g := f.origGID(r)
	if f.newGID != nil {
		if ng, ok := f.newGID[uint32(g)]; ok {
			return ng
		}
		return 0 // 原字体有但子集未收录（理论不可达：used 集由同一 gid 生成）
	}
	return g
}

// origGID 原字体映射查找（format12 二分优先；format4 分段二分）。
func (f *pdfFont) origGID(r rune) uint16 {
	c := uint32(r)
	if len(f.groups) > 0 {
		i := sort.Search(len(f.groups), func(i int) bool { return f.groups[i][1] >= c })
		if i < len(f.groups) && f.groups[i][0] <= c {
			return uint16(f.groups[i][2] + (c - f.groups[i][0]))
		}
		return 0
	}
	if f.cmap4 != nil {
		sub, seg := f.cmap4, f.cmap4Seg
		u16 := func(off int) int { return int(binary.BigEndian.Uint16(sub[off : off+2])) }
		endOff := 14
		startOff := endOff + 2*seg + 2
		deltaOff := startOff + 2*seg
		rangeOff := deltaOff + 2*seg
		lo, hi := 0, seg-1
		i := seg - 1
		for lo <= hi {
			mid := (lo + hi) / 2
			if u16(endOff+2*mid) >= int(c) {
				i, hi = mid, mid-1
			} else {
				lo = mid + 1
			}
		}
		if int(c) < u16(startOff+2*i) || int(c) > u16(endOff+2*i) {
			return 0
		}
		ro := u16(rangeOff + 2*i)
		if ro == 0 {
			return uint16((int(c) + u16(deltaOff+2*i)) & 0xFFFF)
		}
		idx := rangeOff + 2*i + ro + 2*(int(c)-u16(startOff+2*i))
		if idx+2 > len(sub) {
			return 0
		}
		return uint16((u16(idx) + u16(deltaOff+2*i)) & 0xFFFF)
	}
	return 0
}

// glyphLen 原字形数据长度（loca[i+1]-loca[i]）。
func glyphLen(f *pdfFont, gidOrig uint32) int {
	gl, ok := f.tables["glyf"]
	lc, ok2 := f.tables["loca"]
	if !ok || !ok2 || int(gidOrig)+1 >= int(gl.length)/4 {
		return 0
	}
	offA := int(binary.BigEndian.Uint32(f.raw[lc.off+4*gidOrig : lc.off+4*gidOrig+4]))
	offB := int(binary.BigEndian.Uint32(f.raw[lc.off+4*gidOrig+4 : lc.off+4*gidOrig+8]))
	if offB <= offA {
		return 0
	}
	return offB - offA
}

// subsetFont 生成仅含 used GIDs 的 TrueType 子集（确定性；glyf/loca 重建 +
// 复合字形组件 GID 重映射 + maxp.numGlyphs 对账 + head.indexToLocFormat=1；
// cmap/hmtx/name/post/OS-2 裁除——Identity-H 渲染不需要 cmap，/W 未提供=DW 1000）。
func subsetFont(f *pdfFont, used map[uint32]bool) ([]byte, map[uint32]uint16, error) {
	gl, ok := f.tables["glyf"]
	_, ok2 := f.tables["loca"]
	_, ok3 := f.tables["maxp"]
	if !ok || !ok2 || !ok3 {
		return nil, nil, fmt.Errorf("pdf: 字体缺 glyf/loca/maxp，无法子集化")
	}
	// 组件闭包：复合字形引用的组件 GID 一并纳入（递归）。
	work := make([]uint32, 0, len(used))
	for g := range used {
		work = append(work, g)
	}
	seen := make(map[uint32]bool, len(used))
	for g := range used {
		seen[g] = true
	}
	for len(work) > 0 {
		g := work[len(work)-1]
		work = work[:len(work)-1]
		n := glyphLen(f, g)
		if n < 10 {
			continue
		}
		start := int(gl.off) + int(g)*0 // glyf 内偏移由 loca 给出（绝对=gl.off+loca 差）
		_ = start
		goff := int(gl.off) + int(locaOff(f, g))
		data := f.raw[goff : goff+n]
		numContours := int(int16(binary.BigEndian.Uint16(data[0:2])))
		if numContours >= 0 {
			continue // 简单字形：无组件
		}
		p := 10
		for {
			if p+4 > len(data) {
				break
			}
			flags := binary.BigEndian.Uint16(data[p : p+2])
			comp := binary.BigEndian.Uint16(data[p+2 : p+4])
			p += 4
			if flags&0x0001 != 0 { // ARG_1_AND_2_ARE_WORDS
				p += 4
			} else {
				p += 2
			}
			switch { // 缩放参数宽度
			case flags&0x0008 != 0: // WE_HAVE_A_SCALE
				p += 2
			case flags&0x0040 != 0: // X_AND_Y_SCALE
				p += 4
			case flags&0x0080 != 0: // TWO_BY_TWO
				p += 8
			}
			if !seen[uint32(comp)] {
				seen[uint32(comp)] = true
				work = append(work, uint32(comp))
			}
			if flags&0x0020 == 0 { // MORE_COMPONENTS
				break
			}
		}
	}
	// 新 GID 分配：0=.notdef，其余按原 GID 升序（确定性）。
	var sorted []uint32
	for g := range seen {
		sorted = append(sorted, g)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mapping := make(map[uint32]uint16, len(sorted))
	for _, g := range sorted {
		mapping[g] = uint16(len(mapping))
	}
	// 重建 glyf+loca（long）：简单字形逐字节拷贝；复合字形按记录位置重映射组件 GID。
	var glyfBuf bytes.Buffer
	loca := make([]uint32, 0, len(sorted)+1)
	loca = append(loca, 0)
	pad := func(b []byte) []byte {
		if r := len(b) % 4; r != 0 {
			return append(b, make([]byte, 4-r)...)
		}
		return b
	}
	for _, g := range sorted {
		n := glyphLen(f, g)
		if n == 0 {
			loca = append(loca, uint32(glyfBuf.Len()))
			continue
		}
		goff := int(gl.off) + int(locaOff(f, g))
		data := make([]byte, n)
		copy(data, f.raw[goff:goff+n])
		numContours := int(int16(binary.BigEndian.Uint16(data[0:2])))
		if numContours < 0 { // 复合字形：重映射组件 GID
			p := 10
			for {
				flags := binary.BigEndian.Uint16(data[p : p+2])
				patchPos := p + 2
				p += 4
				if flags&0x0001 != 0 {
					p += 4
				} else {
					p += 2
				}
				switch {
				case flags&0x0008 != 0:
					p += 2
				case flags&0x0040 != 0:
					p += 4
				case flags&0x0080 != 0:
					p += 8
				}
				orig := binary.BigEndian.Uint16(data[patchPos : patchPos+2])
				if ng, okk := mapping[uint32(orig)]; okk {
					binary.BigEndian.PutUint16(data[patchPos:patchPos+2], ng)
				}
				if flags&0x0020 == 0 {
					break
				}
			}
		}
		glyfBuf.Write(pad(data))
		loca = append(loca, uint32(glyfBuf.Len()))
	}
	// 组装 sfnt：head/hhea/maxp（打补丁）+ cvt/fpgm/prep（可选保留）+ glyf/loca。
	numGlyphs := len(mapping)
	cp := func(tag string, patches map[int][]byte) ([]byte, error) {
		t, okk := f.tables[tag]
		if !okk {
			return nil, fmt.Errorf("pdf: 子集化缺表 %s", tag)
		}
		b := make([]byte, t.length)
		copy(b, f.raw[t.off:t.off+t.length])
		for off, v := range patches {
			copy(b[off:off+len(v)], v)
		}
		return b, nil
	}
	var idxFmt = []byte{0, 1}
	headB, err := cp("head", map[int][]byte{50: idxFmt})
	if err != nil {
		return nil, nil, err
	}
	hheaB, err := cp("hhea", nil)
	if err != nil {
		return nil, nil, err
	}
	maxpB, err := cp("maxp", map[int][]byte{4: {byte(numGlyphs >> 8), byte(numGlyphs)}})
	if err != nil {
		return nil, nil, err
	}
	locaB := make([]byte, 4*len(loca))
	for i, v := range loca {
		binary.BigEndian.PutUint32(locaB[4*i:4*i+4], v)
	}
	type tbl struct {
		tag  string
		data []byte
	}
	var tabs []tbl
	tabs = append(tabs, tbl{"glyf", glyfBuf.Bytes()}, tbl{"loca", locaB})
	for _, tag := range []string{"cvt ", "fpgm", "prep"} {
		if t, okk := f.tables[tag]; okk {
			tabs = append(tabs, tbl{tag, f.raw[t.off : t.off+t.length]})
		}
	}
	tabs = append(tabs, tbl{"head", headB}, tbl{"hhea", hheaB}, tbl{"maxp", maxpB})
	sort.Slice(tabs, func(i, j int) bool { return tabs[i].tag < tabs[j].tag })
	// sfnt 头 + 表记录（校验和如实计算）+ 数据（4 字节对齐）
	n := len(tabs)
	entrySel := 0
	for 1<<(entrySel+1) <= n {
		entrySel++
	}
	searchRange := (1 << entrySel) * 16
	var out bytes.Buffer
	out.Write([]byte{0, 1, 0, 0})
	for _, v := range []uint16{uint16(n), uint16(searchRange), uint16(entrySel), uint16(n*16 - searchRange)} {
		_ = binary.Write(&out, binary.BigEndian, v)
	}
	records := make([]byte, 16*n)
	pos := 12 + 16*n
	dataSeg := make([][]byte, n)
	for i, t := range tabs {
		copy(records[16*i:16*i+4], t.tag)
		binary.BigEndian.PutUint32(records[16*i+8:16*i+12], uint32(pos))
		binary.BigEndian.PutUint32(records[16*i+12:16*i+16], uint32(len(t.data)))
		binary.BigEndian.PutUint32(records[16*i+4:16*i+8], sfntChecksum(t.data))
		dataSeg[i] = pad(t.data)
		pos += len(dataSeg[i])
	}
	out.Write(records)
	for _, d := range dataSeg {
		out.Write(d)
	}
	return out.Bytes(), mapping, nil
}

// locaOff 原字形在 glyf 表内的偏移（long loca）。
func locaOff(f *pdfFont, g uint32) uint32 {
	lc := f.tables["loca"]
	return binary.BigEndian.Uint32(f.raw[lc.off+4*g : lc.off+4*g+4])
}

// sfntChecksum 表校验和（big-endian 4 字节求和，尾部补零）。
func sfntChecksum(b []byte) uint32 {
	var s uint32
	for i := 0; i < len(b); i += 4 {
		var v uint32
		for j := 0; j < 4 && i+j < len(b); j++ {
			v |= uint32(b[i+j]) << (24 - 8*uint(j))
		}
		s += v
	}
	return s
}

// RenderPDF 报告 → 确定性 PDF 字节流（rep.Text 逐行排版；同报告同字节=AX-3）。
func RenderPDF(rep Report, fontPath string) ([]byte, error) {
	if fontPath == "" {
		return nil, fmt.Errorf("pdf: 未找到 CJK 字体（能力边界：EASM_PDF_FONT 可显式指定）")
	}
	f, err := loadFont(fontPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rep.Text) == "" {
		return nil, fmt.Errorf("pdf: 报告正文为空")
	}
	// 子集化：只嵌正文用到的字形（29MB→~百KB 级），确定性=字形集由文本唯一决定。
	used := map[uint32]bool{0: true}
	for _, r := range rep.Text {
		if g := f.gid(r); g != 0 {
			used[uint32(g)] = true
		}
	}
	sub, mapping, err := subsetFont(f, used)
	if err != nil {
		return nil, err
	}
	f.newGID = mapping

	// 局部变量（非常量）：换行/分页的浮点除法取整需运行期语义（常量截断=编译错）。
	pageW, pageH := 595.0, 842.0 // A4 pt
	margin, size, lineH := 56.0, 10.5, 15.0
	maxChars := int((pageW - 2*margin) / size)
	var lines []string
	for _, ln := range strings.Split(strings.TrimRight(rep.Text, "\n"), "\n") {
		r := []rune(ln)
		for len(r) > maxChars {
			lines, r = append(lines, string(r[:maxChars])), r[maxChars:]
		}
		lines = append(lines, string(r))
	}
	perPage := int(float64(pageH-2*margin) / lineH)
	type page struct{ lines []string }
	var pages []page
	for i := 0; i < len(lines); i += perPage {
		end := i + perPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, page{lines: lines[i:end]})
	}
	if len(pages) == 0 {
		pages = []page{{[]string{""}}}
	}

	streamOf := func(p page) []byte {
		var b bytes.Buffer
		fmt.Fprintf(&b, "BT /F1 %g Tf 1 0 0 1 %d %d Tm\n", size, int(margin), int(float64(pageH-margin-size)))
		y := 0.0
		for _, ln := range p.lines {
			fmt.Fprintf(&b, "0 %g Td <", -y)
			for _, r := range ln {
				fmt.Fprintf(&b, "%04X", f.gid(r))
			}
			b.WriteString("> Tj\n")
			y += lineH
		}
		b.WriteString("ET")
		return b.Bytes()
	}

	fontName := "/" + f.baseName
	kids := make([]string, len(pages))
	for i := range pages {
		kids[i] = fmt.Sprintf("%d 0 R", 7+2*i)
	}
	var bodies []string
	bodies = append(bodies,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)),
		fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont %s /Encoding /Identity-H /DescendantFonts [4 0 R] >>", fontName),
		fmt.Sprintf("<< /Type /Font /Subtype /CIDFontType2 /BaseFont %s /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 5 0 R /DW 1000 >>", fontName),
		fmt.Sprintf("<< /Type /FontDescriptor /FontName %s /Flags 4 /FontBBox [%d %d %d %d] /ItalicAngle 0 /Ascent %d /Descent %d /CapHeight %d /StemV 80 /FontFile2 6 0 R >>",
			fontName, f.bbox[0]*1000/f.upem, f.bbox[1]*1000/f.upem, f.bbox[2]*1000/f.upem, f.bbox[3]*1000/f.upem,
			f.ascent*1000/f.upem, f.descent*1000/f.upem, f.ascent*1000/f.upem),
		fontStream(sub),
	)
	for i := range pages {
		cs := streamOf(pages[i])
		bodies = append(bodies,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", int(pageW), int(pageH), 7+2*i+1),
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(cs), cs))
	}

	// 组装：固定对象序 1..N，写完实体再回填 xref（确定性）。
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offs := make([]int, len(bodies))
	for i, body := range bodies {
		offs[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xrefAt := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(bodies)+1)
	for _, o := range offs {
		fmt.Fprintf(&buf, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(bodies)+1, xrefAt)
	return buf.Bytes(), nil
}
