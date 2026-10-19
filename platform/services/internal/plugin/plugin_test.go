package plugin

import (
	"context"
	"errors"
	"testing"
)

func valid() Contract {
	return Contract{
		ID: "dsh-tool-asm-subfinder", Cmd: "subfinder -d {domain} -all -silent -json -o /out.jsonl",
		Src: "github.com/projectdiscovery/subfinder", Cap: "discover", Risk: "只读",
		Auth: false, Lic: "MIT", Out: "subdomains[]", SubCode: "MAP-2",
		Image: "easm/tool-subfinder:1.6.2", ResClass: "M", NetClass: "passive", LicMode: "main-image",
	}
}

// 为什么（FR-PLG-001/004/005）：契约即护栏——id 格式/枚举/镜像 tag 锁定/授权联动/
// 许可证隔离任一漂移都让「注册即安全运行」承诺失效；错误信息必须直指字段。
func TestContractValidation(t *testing.T) {
	c0 := valid()
	if err := (&c0).Validate(); err != nil {
		t.Fatalf("合法契约应通过: %v", err)
	}
	cases := []struct {
		name  string
		mut   func(*Contract)
		wants []string // 错误必须包含的字段提示
	}{
		{"id 非法", func(c *Contract) { c.ID = "subfinder" }, []string{"id"}},
		{"缺 out", func(c *Contract) { c.Out = "" }, []string{"out"}},
		{"缺 cmd", func(c *Contract) { c.Cmd = "" }, []string{"cmd"}},
		{"risk 非法", func(c *Contract) { c.Risk = "危险" }, []string{"risk"}},
		{"net 非法", func(c *Contract) { c.NetClass = "open" }, []string{"net_class"}},
		{"res 非法", func(c *Contract) { c.ResClass = "XXL" }, []string{"res_class"}},
		{"latest 镜像", func(c *Contract) { c.Image = "easm/tool-subfinder:latest" }, []string{"image"}},
		{"无 tag", func(c *Contract) { c.Image = "easm/tool-subfinder" }, []string{"image"}},
		{"主动未授权", func(c *Contract) { c.NetClass = "active-high" }, []string{"C-4", "authz"}},
		{"AGPL 进主镜像", func(c *Contract) { c.Lic = "AGPL-3.0" }, []string{"cli_subprocess"}},
		{"GPL 进主镜像", func(c *Contract) { c.Lic = "GPL-3.0" }, []string{"cli_subprocess"}},
		{"NPSL 进主镜像", func(c *Contract) { c.Lic = "NPSL" }, []string{"cli_subprocess"}},
	}
	for _, tc := range cases {
		c := valid()
		tc.mut(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
			continue
		}
		if !errors.Is(err, ErrContract) {
			t.Errorf("%s: 应包装 ErrContract", tc.name)
		}
		for _, w := range tc.wants {
			if !contains(err.Error(), w) {
				t.Errorf("%s: 错误应含 %q，实际 %v", tc.name, w, err)
			}
		}
	}
	// AGPL + cli_subprocess 组合必须放行（trufflehog 的合法形态）
	c := valid()
	c.Lic, c.LicMode = "AGPL-3.0", "cli_subprocess"
	c.ID, c.Image = "dsh-tool-leak-trufflehog", "easm/tool-trufflehog:3.88"
	if err := c.Validate(); err != nil {
		t.Errorf("AGPL+cli_subprocess 应通过: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// 为什么（FR-PLG-002 / 一票否决⑩）：热注册/卸载立即生效且互不影响——
// 若卸载把其他插件带崩或注册不生效，「新增能力不改平台」即谎言。
func TestHotRegisterUnregister(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()
	a, b := valid(), valid()
	b.ID, b.Image, b.Cap = "dsh-tool-scan-nuclei", "easm/tool-nuclei:3.3.7", "scan"
	if err := r.Register(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ctx, a); !errors.Is(err, ErrDuplicate) {
		t.Error("重复 id 应拒绝")
	}
	bad := valid()
	bad.ID = "junk"
	if err := r.Register(ctx, bad); !errors.Is(err, ErrContract) {
		t.Error("非法契约不得进入注册表")
	}
	if got := r.List(""); len(got) != 2 {
		t.Fatalf("应 2 个插件，实际 %d", len(got))
	}
	if err := r.Unregister(ctx, "dsh-tool-asm-subfinder"); err != nil {
		t.Fatal(err)
	}
	if got := r.List(""); len(got) != 1 || got[0].ID != "dsh-tool-scan-nuclei" {
		t.Errorf("卸载后应仅剩 nuclei，实际 %+v", got)
	}
	if err := r.Unregister(ctx, "dsh-tool-asm-subfinder"); !errors.Is(err, ErrNotFound) {
		t.Error("卸载不存在应 ErrNotFound")
	}
	// 能力域过滤
	if got := r.List("discover"); len(got) != 0 {
		t.Error("subfinder 已卸载，discover 过滤应为空")
	}
}
