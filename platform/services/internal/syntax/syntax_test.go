package syntax

import (
	"errors"
	"strings"
	"testing"
)

// 为什么（FR-SYN-001 / 一票否决①延伸）：分组结构是「工作文件语法类型一一对应」的验收口径，
// 漂移即监管验收失败。
func TestCatalogStructure(t *testing.T) {
	cat := Catalog()
	byPh := map[string]int{}
	for _, g := range cat {
		byPh[g.Ph]++
	}
	if len(cat) != 12 || byPh["P1"] != 5 || byPh["P2"] != 4 || byPh["P3"] != 3 {
		t.Errorf("应为 12 组（P1 五/P2 四/P3 三），实际 %d %+v", len(cat), byPh)
	}
	for _, g := range cat {
		if len(g.Items) == 0 || len(g.Engs) == 0 {
			t.Errorf("组 %s 不完整", g.G)
		}
	}
}

// 为什么（AC2 / F5.4）：实例化 ≥16 条且绝无占位符残留——残留语句直接不可执行。
func TestRenderNoPlaceholder(t *testing.T) {
	out, err := Render(RenderInput{Org: "华东联合数据服务集团有限公司", Short: "华东数服", Domain: "HDDATA.cn", CIDR: "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 16 {
		t.Fatalf("应 ≥16 条，实际 %d", len(out))
	}
	for _, st := range out {
		if strings.ContainsAny(st.Stmt, "{}") {
			t.Errorf("占位符残留: %q", st.Stmt)
		}
	}
	// 域名归一与占位符替换的正确性抽查
	var hit bool
	for _, st := range out {
		if st.Stmt == "site:hddata.cn" {
			hit = true
		}
	}
	if !hit {
		t.Error("site:{domain} 应实例化为 site:hddata.cn（小写归一）")
	}
	// 四参数缺任一必须拒绝（否则产生半渲染语句）
	if _, err := Render(RenderInput{Org: "x", Short: "y", Domain: "z.cn"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("缺 cidr 应拒绝，实际 %v", err)
	}
}

// 为什么（FR-DSC-008）：ext: 仅限百度/必应，Fofa 必须键值语法——方言混用=执行必败。
func TestDialectGate(t *testing.T) {
	if _, ok := Dialect("Fofa", `domain="hddata.cn"`); !ok {
		t.Error("Fofa 键值语法应通过")
	}
	if _, ok := Dialect("Fofa", "site:hddata.cn"); ok {
		t.Error("Fofa 收到 site: 应判不合规（需转换 domain=）")
	}
	if _, ok := Dialect("百度", "site:hddata.cn filetype:sql"); !ok {
		t.Error("百度高级语法应通过")
	}
}

// 阶段筛选（FR-SYN-003）。
func TestFilterPhase(t *testing.T) {
	if len(FilterPhase("P2")) != 4 {
		t.Error("P2 应 4 组")
	}
	if len(FilterPhase("")) != 12 {
		t.Error("空阶段应全量 12 组")
	}
}
