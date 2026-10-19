// Package syntax 实现检索语法库（FR-SYN-001~005 / F5）：
// 12 组目录逐条对齐工作文件（P1 五类×3引擎 / P2 四类×测绘 / P3 三类扫描策略）；
// 实例化=占位符确定性替换（无模型，AX-2），方言转换按引擎白名单校验（FR-DSC-008）。
package syntax

import (
	"errors"
	"regexp"
	"strings"
)

var ErrInvalidInput = errors.New("syntax: invalid render input")

type Entry struct {
	S    string `json:"s"`    // 语句模板（含 {org}/{short}/{domain}/{cidr} 占位符；P3 为扫描策略）
	D    string `json:"d"`    // 说明
	Kind string `json:"kind"` // search | scan
}

type Group struct {
	G     string   `json:"g"`
	Ph    string   `json:"ph"`
	Engs  []string `json:"eng"`
	Note  string   `json:"d"`
	Items []Entry  `json:"items"`
}

func s(e string, d string, kind string) Entry { return Entry{S: e, D: d, Kind: kind} }

// Catalog 12 组（FR-SYN-001 验收：P1 五组 / P2 四组 / P3 三组）。
func Catalog() []Group {
	return []Group{
		{G: "全域站点检索", Ph: "P1", Engs: []string{"百度", "搜狗", "必应"}, Note: "锁定官方主站及关联合规站点", Items: []Entry{
			s("site:{domain}", "主域全量收录站点", "search"),
			s("\"{org}\"", "单位全称关联页面", "search"),
			s("\"{short}\" (官网|站点)", "简称+官网语境", "search"),
		}},
		{G: "敏感附件检索", Ph: "P1", Engs: []string{"百度", "必应"}, Note: " filetype 检索涉密附件", Items: []Entry{
			s("site:{domain} filetype:pdf 方案", "PDF 方案类附件", "search"),
			s("site:{domain} filetype:doc 会议纪要", "DOC 纪要类", "search"),
			s("site:{domain} filetype:xls 通讯录", "XLS 表格泄露", "search"),
			s("site:{domain} filetype:ppt 培训", "PPT 内部培训", "search"),
		}},
		{G: "后台入口检索", Ph: "P1", Engs: []string{"百度", "搜狗", "必应"}, Note: "管理后台/登录入口暴露", Items: []Entry{
			s("site:{domain} inurl:admin", "admin 路径", "search"),
			s("site:{domain} inurl:login", "login 路径", "search"),
			s("site:{domain} 后台登录", "标题含后台登录", "search"),
			s("site:{domain} inurl:manage inurl:console", "manage/console 路径", "search"),
		}},
		{G: "公开信息泄露检索", Ph: "P1", Engs: []string{"百度", "搜狗", "必应"}, Note: "身份证/手机号/邮箱等外露", Items: []Entry{
			s("site:{domain} \"身份证\"", "身份证字样页面", "search"),
			s("site:{domain} \"联系电话\"", "联系电话聚合页", "search"),
			s("site:{domain} \"@{domain}\"", "单位邮箱外露", "search"),
			s("\"{org}\" \"花名册\"", "全网花名册线索", "search"),
		}},
		{G: "备份文件检索", Ph: "P1", Engs: []string{"百度", "必应"}, Note: "备份/安装包/数据库文件", Items: []Entry{
			s("site:{domain} filetype:zip 备份", "ZIP 备份件", "search"),
			s("site:{domain} filetype:sql", "SQL 转储", "search"),
			s("site:{domain} filetype:bak", "BAK 备份", "search"),
			s("site:{domain} inurl:backup", "backup 目录", "search"),
		}},
		{G: "主体精准检索", Ph: "P2", Engs: []string{"Fofa", "Quake", "Hunter"}, Note: "主体维度测绘归集", Items: []Entry{
			s(`title="{org}"`, "标题含单位全称", "search"),
			s(`cert.subject="{org}"`, "证书主题匹配", "search"),
			s(`icp.region!="" && domain="{domain}"`, "备案关联域名（Fofa）", "search"),
			s(`footer="{short}"`, "页脚含简称", "search"),
		}},
		{G: "域名全域检索", Ph: "P2", Engs: []string{"Fofa", "Quake", "Hunter"}, Note: "主域+子域", Items: []Entry{
			s(`domain="{domain}"`, "主域及子域", "search"),
			s(`host=~"\\.?{domain}"`, "泛前缀匹配", "search"),
			s(`domain="{domain}" && protocol="https"`, "HTTPS 面", "search"),
			s(`domain="{domain}" && is_domain=true`, "仅域名资产", "search"),
		}},
		{G: "IP 段精准检索", Ph: "P2", Engs: []string{"Fofa", "Quake", "Hunter"}, Note: "授权网段", Items: []Entry{
			s(`ip="{cidr}"`, "网段全量资产", "search"),
			s(`ip="{cidr}" && port=443`, "网段 HTTPS", "search"),
			s(`ip="{cidr}" && country="CN"`, "境内资产复核", "search"),
			s(`ip="{cidr}" && server`, "组件 banner", "search"),
		}},
		{G: "证书盲区摸排", Ph: "P2", Engs: []string{"crt.sh"}, Note: "CT 日志派生子域", Items: []Entry{
			s(`%.{domain}`, "通配符反查 SAN", "search"),
			s(`SELECT name FROM ct WHERE name LIKE '%.{domain}'`, "crt.sh 查询语句", "search"),
			s(`{domain} 全部证书`, "主域证书全集", "search"),
		}},
		{G: "全域端口扫描", Ph: "P3", Engs: []string{"Nmap"}, Note: "授权范围端口/服务", Items: []Entry{
			s("nmap -sV -p- --min-rate 1000 {cidr}", "全端口+服务版本（限速）", "scan"),
			s("nmap -sV -p 21,22,23,80,443,445,1433,3306,3389,5432,6379,9200,27017 {cidr}", "高危端口清单", "scan"),
			s("nmap -sC -sV {domain}", "默认脚本+指纹", "scan"),
			s("nmap -Pn --open {cidr}", "存活+开放端口过滤", "scan"),
		}},
		{G: "目录爆破探测", Ph: "P3", Engs: []string{"Dirsearch", "御剑"}, Note: "后台/隐藏目录", Items: []Entry{
			s("dirsearch -u https://{domain} -e php,asp,jsp,bak,zip -r", "动态字典（技术栈生成）", "scan"),
			s("御剑 全字典扫描 https://{domain}", "后台路径枚举", "scan"),
			s("dirsearch -u https://{domain} -f admin,manager,console,login", "后台小字典", "scan"),
		}},
		{G: "敏感文件筛查", Ph: "P3", Engs: []string{"Dirsearch", "御剑"}, Note: "备份/配置/源码包", Items: []Entry{
			s("dirsearch -u https://{domain} -w backup.txt,config.txt,source.txt", "敏感文件字典", "scan"),
			s("curl -sf https://{domain}/.git/HEAD", "git 仓库裸露", "scan"),
			s("curl -sf https://{domain}/web.config", "配置文件裸露", "scan"),
			s("御剑 敏感文件扩展名扫描 https://{domain}", "备份/DB/压缩包", "scan"),
		}},
	}
}

// FilterPhase 按阶段筛选（FR-SYN-003）。
func FilterPhase(ph string) []Group {
	all := Catalog()
	if ph == "" || ph == "all" {
		return all
	}
	out := make([]Group, 0, 5)
	for _, g := range all {
		if g.Ph == ph {
			out = append(out, g)
		}
	}
	return out
}

var rxPlaceholder = regexp.MustCompile(`\{[a-z]+\}`)

// RenderInput 实例化输入（F5.4：全称/简称/主域/IP 段）。
type RenderInput struct {
	Org    string `json:"org"`
	Short  string `json:"short"`
	Domain string `json:"domain"`
	CIDR   string `json:"cidr"`
}

type Statement struct {
	Phase  string `json:"phase"`
	Intent string `json:"intent"`
	Engine string `json:"engine"`
	Stmt   string `json:"statement"`
	Note   string `json:"note"`
}

// Render 全部条目×引擎实例化；四参数必填；输出保证无占位符残留（AC2）。
func Render(in RenderInput) ([]Statement, error) {
	if in.Org == "" || in.Short == "" || in.Domain == "" || in.CIDR == "" {
		return nil, ErrInvalidInput
	}
	domain := strings.ToLower(strings.TrimSpace(in.Domain))
	cidr := strings.TrimSpace(in.CIDR)
	rep := strings.NewReplacer("{org}", in.Org, "{short}", in.Short, "{domain}", domain, "{cidr}", cidr)
	var out []Statement
	for _, g := range Catalog() {
		for _, it := range g.Items {
			for _, eng := range g.Engs {
				stmt := rep.Replace(it.S)
				if rxPlaceholder.MatchString(stmt) {
					return nil, errors.New("syntax: 渲染后仍有占位符残留 " + stmt)
				}
				out = append(out, Statement{Phase: g.Ph, Intent: g.G, Engine: eng, Stmt: stmt, Note: it.D})
			}
		}
	}
	return out, nil
}

// Dialect 跨引擎方言校验（FR-DSC-008）：ext: 仅百度/必应；Fofa/Quake/Hunter 用键值语法。
func Dialect(eng, stmt string) (string, bool) {
	switch eng {
	case "百度", "必应":
		if strings.Contains(stmt, "site:") || strings.Contains(stmt, "filetype:") || strings.Contains(stmt, "inurl:") {
			return "ok", true
		}
		return "建议改用 site:/filetype:/inurl: 高级语法", true
	case "搜狗":
		if strings.Contains(stmt, "site:") {
			return "ok（搜狗支持 site:）", true
		}
		return "搜狗对 filetype: 支持有限，命中不足时切换百度/必应", true
	case "Fofa", "Quake", "Hunter":
		if strings.ContainsAny(stmt, "=") {
			return "ok（键值语法）", true
		}
		return "需转换为 domain=/ip=/title=/cert= 键值语法", false
	case "crt.sh":
		return "crt.sh 查询接口格式", true
	default:
		return "未知引擎", false
	}
}
