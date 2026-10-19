// Package plugin 实现工具插件注册中心（FR-PLG-001~006 / F18.2 / 一票否决⑩关联）。
// 8 字段注册契约（来源 B）+ 容器安全规格字段 + 许可证护栏 + 危险级别×授权联动（C-4）。
// 新增能力=注册新契约，平台零扫描逻辑（AX-6）；热注册/卸载不重启（FR-PLG-002）。
package plugin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	ErrContract  = errors.New("plugin: contract validation failed")
	ErrDuplicate = errors.New("plugin: duplicate id")
	ErrNotFound  = errors.New("plugin: not found")
)

// Contract 8 字段 + 运行规格字段（DR-10 对齐）。
type Contract struct {
	ID       string `json:"id"`   // dsh-tool-<domain>-<name>
	Cmd      string `json:"cmd"`  // CLI 命令模板
	Src      string `json:"src"`  // 来源仓库
	Cap      string `json:"cap"`  // 能力域
	Risk     string `json:"risk"` // 只读 | 受控 | 高危
	Auth     bool   `json:"auth"` // requires_authz
	Lic      string `json:"lic"`  // 许可证
	Out      string `json:"out"`  // 输出契约（→ Candidate）
	SubCode  string `json:"sub_code"`
	Image    string `json:"image"`     // easm/tool-<name>:<ver>（tag 锁定）
	ResClass string `json:"res_class"` // S|M|L|XL
	NetClass string `json:"net_class"` // passive|active-low|active-high|cloud
	LicMode  string `json:"lic_mode"`  // main-image | cli_subprocess
}

var (
	rxID       = regexp.MustCompile(`^dsh-tool-[a-z0-9]+(-[a-z0-9]+)*$`)
	rxImage    = regexp.MustCompile(`^easm/tool-[a-z0-9-]+:[0-9][A-Za-z0-9._-]*$`) // tag 锁定，禁 latest
	risks      = map[string]bool{"只读": true, "受控": true, "高危": true}
	netCls     = map[string]bool{"passive": true, "active-low": true, "active-high": true, "cloud": true}
	resCls     = map[string]bool{"S": true, "M": true, "L": true, "XL": true}
	infectious = regexp.MustCompile(`(?i)AGPL|^GPL|GPL-[23]|NPSL|LGPL`)
)

// Validate 契约校验；返回首个问题（fail loud：错误信息直指字段）。
func (c *Contract) Validate() error {
	if c.LicMode == "" {
		c.LicMode = "main-image" // 默认值规范化持久化（注册表内不留空值）
	}
	var bad []string
	if !rxID.MatchString(c.ID) {
		bad = append(bad, "id 必须匹配 dsh-tool-<domain>-<name>，实际 "+c.ID)
	}
	for k, v := range map[string]string{"cmd": c.Cmd, "src": c.Src, "cap": c.Cap, "lic": c.Lic, "out": c.Out, "sub_code": c.SubCode} {
		if strings.TrimSpace(v) == "" {
			bad = append(bad, k+" 缺失")
		}
	}
	if !risks[c.Risk] {
		bad = append(bad, "risk 必须为 只读/受控/高危")
	}
	if !netCls[c.NetClass] {
		bad = append(bad, "net_class 非法（passive/active-low/active-high/cloud）")
	}
	if !resCls[c.ResClass] {
		bad = append(bad, "res_class 非法（S/M/L/XL）")
	}
	if !rxImage.MatchString(c.Image) {
		bad = append(bad, "image 必须 tag 锁定 easm/tool-<name>:<ver>，禁 latest："+c.Image)
	}
	// C-4 权限口径同源：主动/云端网络级别必须声明授权要求
	if (c.NetClass == "active-high" || c.NetClass == "cloud") && !c.Auth {
		bad = append(bad, "active-high/cloud 工具必须 requires_authz=true（C-4）")
	}
	// 许可证护栏（FR-PLG/护栏 3）：传染性许可证 → 仅 CLI 子进程形态
	if infectious.MatchString(c.Lic) && c.LicMode != "cli_subprocess" {
		bad = append(bad, fmt.Sprintf("许可证 %s 具传染性，lic_mode 必须 cli_subprocess", c.Lic))
	}
	if c.LicMode != "main-image" && c.LicMode != "cli_subprocess" {
		bad = append(bad, "lic_mode 非法（main-image/cli_subprocess）")
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: %s", ErrContract, strings.Join(bad, "; "))
	}
	return nil
}

type Registry struct {
	mu       sync.RWMutex
	register map[string]Contract
	history  map[string]int // 注册次数（观测/审计用）
}

func NewRegistry() *Registry {
	return &Registry{register: map[string]Contract{}, history: map[string]int{}}
}

// Register 热注册（FR-PLG-002）：契约校验通过才装载；重复 id 拒绝。
func (r *Registry) Register(_ context.Context, c Contract) error {
	if err := c.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.register[c.ID]; dup {
		return ErrDuplicate
	}
	r.register[c.ID] = c
	r.history[c.ID]++
	return nil
}

// Unregister 热卸载：立即从模型可见集合移除，不影响其他插件与主干。
func (r *Registry) Unregister(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.register[id]; !ok {
		return ErrNotFound
	}
	delete(r.register, id)
	return nil
}

// Get 查询单个契约（MCP 网关分级依据，C-4 同源）。
func (r *Registry) Get(id string) (Contract, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.register[id]
	return c, ok
}

// List 按 id 排序输出（确定性）。cap 非空按能力域过滤。
func (r *Registry) List(cap string) []Contract {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Contract, 0, len(r.register))
	for _, c := range r.register {
		if cap != "" && c.Cap != cap {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
