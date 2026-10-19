package classify

// Engine 无状态规则引擎；热更新（NFR-SCL-004）在 M1 通过重建实例实现。
type Engine struct {
	rules []Rule
}

func New() *Engine { return &Engine{rules: allRules()} }

func (e *Engine) Detect(content string, in Input) []Hit {
	var out []Hit
	for _, r := range e.rules {
		for _, h := range r.run(content, in) {
			h.RuleName = r.Name
			if h.Level == "" {
				h.Level = r.Level
			}
			out = append(out, h)
		}
	}
	return out
}

// ---- 目录（34 敏感项逐字对齐 PRD F6 / 一票否决②）----

type CatalogCat struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Level string     `json:"level"`
	Items []string   `json:"items"`
	Rules []RuleView `json:"rules"`
}

type RuleView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Logic  string `json:"logic"`
	Method string `json:"method"`
	Level  string `json:"level"`
}

var catalogItems = map[string][]string{
	CatSys: {
		"未备案域名", "隐蔽子域名", "内网系统地址", "公网管理后台入口", "网络设备管理地址",
		"高危开放端口", "网络拓扑图和架构设计文档", "系统部署方案和实施指南", "技术选型和版本信息",
		"设备型号和固件版本", "软件授权码和序列号", "网络设备配置备份",
	},
	CatCred: {
		"业务源码", "系统密钥", "账号密码", "服务器路径", "服务器 SSH 密钥和登录凭证",
		"数据库配置", "数据库连接字符串和密码", "数据库备份", "开发测试数据", "API 密钥和认证令牌",
	},
	CatBiz: {
		"单位组织架构", "内部通讯录", "核心人员信息", "人事档案", "招投标文件", "客户信息",
		"项目方案", "合同协议", "财务报表", "运维台账", "会议纪要", "技术手册",
	},
}

var catalogLevel = map[string]string{CatSys: "高", CatCred: "严重", CatBiz: "高"}

func (e *Engine) Catalog() []CatalogCat {
	order := []string{CatSys, CatCred, CatBiz}
	ids := map[string]string{CatSys: "C1", CatCred: "C2", CatBiz: "C3"}
	out := make([]CatalogCat, 0, 3)
	for _, name := range order {
		c := CatalogCat{ID: ids[name], Name: name, Level: catalogLevel[name], Items: catalogItems[name]}
		for _, r := range e.rules {
			if r.Cat == name {
				c.Rules = append(c.Rules, RuleView{ID: r.ID, Name: r.Name, Logic: r.Logic, Method: r.Method, Level: r.Level})
			}
		}
		out = append(out, c)
	}
	return out
}
