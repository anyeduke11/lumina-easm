package classify

import (
	"regexp"
	"strconv"
	"strings"
)

func mk(cat, id, name, logic, method, level string, run func(string, Input) []Hit) Rule {
	return Rule{ID: id, Name: name, Cat: cat, Logic: logic, Method: method, Level: level, run: run}
}

// rxHits 全串匹配（group 0）转 Hit，片段截断 120 字符。
func rxHits(rx *regexp.Regexp, id, cat, level, text string) []Hit {
	var out []Hit
	for _, b := range rx.FindAllStringIndex(text, -1) {
		s := text[b[0]:b[1]]
		if len(s) > 120 {
			s = s[:120]
		}
		out = append(out, Hit{RuleID: id, Category: cat, Level: level, Snippet: s, Start: b[0], End: b[1]})
	}
	return out
}

func firstSub(rx *regexp.Regexp, text string) []subMatch {
	ms := rx.FindAllStringIndex(text, -1)
	out := make([]subMatch, 0, len(ms))
	for _, b := range ms {
		out = append(out, subMatch{s: text[b[0]:b[1]], start: b[0], end: b[1]})
	}
	return out
}

var (
	rxIntra  = re(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	rxAdmin  = re(`(?i)(/admin(?:\.php|/index)?|/login(?:\.php)?|后台入口|管理后台|phpmyadmin|adminer|/manager/html|nacos|jenkins/login|kuboard)`)
	rxDevice = re(`(?i)(Cisco IOS|Huawei (?:VRP|S\d{4})|H3C Comware|Ruijie(?: ?OS)?|深信服|天融信|Juniper JUNOS)[^<\n]{0,40}?[Vv]ersion\s*[\d.]+|固件版本\s*[:：=]?\s*[\d.]+`)
	rxHidden = re(`(?i)(/\.git/|/\.svn/|/\.env\b|/\.ds_store|/backup/|/wwwroot|web\.config|/\.ssh/|/\.aws/|server-status)`)
	rxTopo   = re(`(?i)(网络拓扑图|拓扑图|架构图|系统架构设计|网络架构设计|\.vsd[x]?|\.drawio|\.eddx|\.rsp\b)`)
	rxVer    = re(`(?i)(server:\s*(?:nginx|apache|IIS)/[\d.]+|x-powered-by:\s*[\w./ -]+|tomcat/[\d.]+|jboss|weblogic|用友|金蝶|泛微)[ /]?[\d.]*|版本信息\s*[:：]\s*[\d.]+`)
	rxComp   = re(`(?i)[a-z][\w.-]*/\d+\.\d+(?:\.\d+)?`)

	rxPriv   = re(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)
	rxJDBC   = re(`(?i)jdbc:(?:mysql|oracle|sqlserver|postgresql|mongodb)://[^\s"']*(?:user=|password=|pwd=|[?&;](?:u|p)=|://[^/@\s"']+:[^/@\s"']+@)[^\s"']*`)
	rxKeyPfx = re(`(?i)\b(AKIA[A-Z0-9]{16}|LTAI[A-Za-z0-9]{12,24}|AKID[A-Za-z0-9]{13,20}|gh[pousr]_[A-Za-z0-9]{36,}|sk_live_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{32,}|xox[bpse]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`)
	rxToken  = re(`[A-Za-z0-9+/=_$@.#-]{20,}`)
	rxHard   = re(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*["']?[^\s"'=;,]{6,}`)
	rxSrc    = re(`(?i)(\.git\b|\.svn\b|src\.zip|source\.zip|[\w.-]+\.war\b|[\w.-]+\.jar\b|/WEB-INF/|web\.xml|\.ssh/id_[a-z]+)`)
	rxBak    = re(`(?i)((?:redis|mysql|pgsql|mongo|oracle|elasticsearch)\.password\s*[=:]|\[mysqld\]|application[-.]?(?:properties|ya?ml)|config\.(?:php|py|js)|\.bak\b|running-config|startup-config)`)
	rxPath   = re(`(?i)(/var/www|/etc/(?:passwd|shadow|nginx|ssh)|/usr/local/tomcat|/home/[a-z0-9_]+/|c:\\\\users\\\\|d:\\\\wwwroot)`)
	rxDB     = re(`(?i)(--\s*(?:mysql|pg)_?dump\b|CREATE\s+DATABASE|CREATE\s+TABLE|INSERT\s+INTO\s+["` + "`" + `\w]|SQLite format 3|\.sql\.gz\b|数据库备份)`)
	rxTest   = re(`(?i)(测试数据|testdata|seed\.sql|faker|mock[_-]?user|演示数据)`)

	rxContact = re(`(?i)(通讯录|组织架构|花名册|组织结构图|内部联系人)`)
	rxBizDoc  = re(`(?i)(投标文件|招标(?:文件|公告)|项目方案|合同协议|会议纪要|内部制度|运维(?:手册|台账|记录)|技术手册|实施指南|部署方案)`)
	rxMeta    = re(`(?i)(dc:creator|cp:author|(?:作者|最后修改者)\s*[:：=]\s*[\w\p{Han}]{2,}|company\s*[:：=]\s*[\w\p{Han}]{2,}|Producer\s+Microsoft)`)
	rxCust    = re(`(?i)(客户(?:信息|名单|编号|单位)|customer\s*(?:info|list)|(?:客户|用户)\D{0,12}(?:身份证|手机号|银行账[号户]|账户余额))`)
	rxFin     = re(`(?i)(资产负债表|利润表|现金流量表|财务报表|审计报告|净利润|营收)`)

	dangerPorts = map[int]string{23: "telnet", 445: "smb", 1433: "mssql", 1521: "oracle", 2375: "docker-api", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
)

func allRules() []Rule {
	return []Rule{
		// ---- 系统架构类（7）----
		mk(CatSys, "R-INTRANET", "内网地址识别", "私有网段 10/8、172.16/12、192.168/16 正则，排除公网映射误报", "正则匹配", "高",
			func(t string, _ Input) []Hit { return rxHits(rxIntra, "R-INTRANET", CatSys, "高", t) }),
		mk(CatSys, "R-ADMIN", "后台入口识别", "公网可达管理后台路径/标题特征", "正则+标题特征", "高",
			func(t string, in Input) []Hit {
				out := rxHits(rxAdmin, "R-ADMIN", CatSys, "高", t)
				return append(out, rxHits(rxAdmin, "R-ADMIN", CatSys, "高", in.Title)...)
			}),
		mk(CatSys, "R-DEVICE", "设备指纹识别", "网络设备型号/固件版本暴露", "正则+Banner", "高",
			func(t string, _ Input) []Hit { return rxHits(rxDevice, "R-DEVICE", CatSys, "高", t) }),
		mk(CatSys, "R-HIDDEN", "隐藏路径识别", "版本库/配置/备份等隐藏路径匿名可达", "路径正则", "高",
			func(t string, in Input) []Hit {
				out := rxHits(rxHidden, "R-HIDDEN", CatSys, "高", t)
				return append(out, rxHits(rxHidden, "R-HIDDEN", CatSys, "高", in.URL)...)
			}),
		mk(CatSys, "R-PORT", "高危端口识别", "服务端口公网暴露；无认证上下文升级严重（FR-DSC-014）", "结构化端口+上下文", "高",
			func(t string, in Input) []Hit {
				var out []Hit
				lc := strings.ToLower(t)
				noAuth := strings.Contains(lc, "no auth") || strings.Contains(t, "无认证") || strings.Contains(t, "免密") || strings.Contains(lc, "requirepass no")
				for _, p := range in.Ports {
					if svc, ok := dangerPorts[p]; ok {
						lv := "高"
						ex := ""
						if noAuth {
							lv = "严重"
							ex = "（无认证）"
						}
						out = append(out, Hit{RuleID: "R-PORT", Category: CatSys, Level: lv,
							Snippet: strconv.Itoa(p) + "/tcp " + svc + ex})
					}
				}
				return out
			}),
		mk(CatSys, "R-TOPO", "拓扑架构文档识别", "网络拓扑/架构设计文档外泄特征", "关键词+扩展名", "高",
			func(t string, _ Input) []Hit { return rxHits(rxTopo, "R-TOPO", CatSys, "高", t) }),
		mk(CatSys, "R-VERSION", "技术版本暴露识别", "Banner/响应头/组件版本串暴露", "正则+tech 字段", "中",
			func(t string, in Input) []Hit {
				out := rxHits(rxVer, "R-VERSION", CatSys, "中", t)
				if len(out) == 0 {
					out = rxHits(rxComp, "R-VERSION", CatSys, "中", strings.Join(in.Tech, " "))
				}
				return out
			}),

		// ---- 代码密码类（8）----
		mk(CatCred, "R-PRIVKEY", "私钥识别", `匹配 -----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`, "正则匹配", "严重",
			func(t string, _ Input) []Hit { return rxHits(rxPriv, "R-PRIVKEY", CatCred, "严重", t) }),
		mk(CatCred, "R-CONNSTR", "连接串识别", `匹配 jdbc:(mysql|oracle|sqlserver|postgresql):// 且携带凭据`, "正则匹配", "严重",
			func(t string, _ Input) []Hit { return rxHits(rxJDBC, "R-CONNSTR", CatCred, "严重", t) }),
		mk(CatCred, "R-KEY", "密钥识别", "已知凭据前缀命中即报；无前缀令牌要求长度≥20 且 Shannon 熵>4.5 且字符多样性≥12", "前缀+熵值判定", "严重",
			func(t string, _ Input) []Hit {
				var out []Hit
				for _, m := range firstSub(rxKeyPfx, t) {
					out = append(out, Hit{RuleID: "R-KEY", Category: CatCred, Level: "严重", Snippet: mask(m.s), Start: m.start, End: m.end})
				}
				if len(out) == 0 {
					for _, m := range firstSub(rxToken, t) {
						if shannon(m.s) > 4.5 && countDistinct(m.s) >= 12 {
							out = append(out, Hit{RuleID: "R-KEY", Category: CatCred, Level: "严重", Snippet: mask(m.s), Start: m.start, End: m.end})
							break
						}
					}
				}
				return out
			}),
		mk(CatCred, "R-HARDCODE", "硬编码凭据识别", "配置/源码中的键值对凭据", "正则匹配", "严重",
			func(t string, _ Input) []Hit {
				var out []Hit
				for _, m := range firstSub(rxHard, t) {
					out = append(out, Hit{RuleID: "R-HARDCODE", Category: CatCred, Level: "严重", Snippet: mask(m.s), Start: m.start, End: m.end})
				}
				return out
			}),
		mk(CatCred, "R-SRCPKG", "源码包识别", "版本库/源码归档/部署包特征（.git/.svn/src.zip/war/jar）", "文件名正则", "严重",
			func(t string, _ Input) []Hit { return rxHits(rxSrc, "R-SRCPKG", CatCred, "严重", t) }),
		mk(CatCred, "R-CONFBAK", "配置备份识别", "应用/设备配置文件与备份件键值结构", "键值结构+文件名", "严重",
			func(t string, _ Input) []Hit { return rxHits(rxBak, "R-CONFBAK", CatCred, "严重", t) }),
		mk(CatCred, "R-SRVPATH", "服务器路径识别", "服务器绝对路径暴露（Web 根/系统凭据文件/家目录）", "路径正则", "高",
			func(t string, _ Input) []Hit { return rxHits(rxPath, "R-SRVPATH", CatCred, "高", t) }),
		mk(CatCred, "R-DBBAK", "数据库备份识别", "SQL dump 头/备份件内容指纹（FR-DSC-016）", "内容指纹正则", "严重",
			func(t string, _ Input) []Hit { return rxHits(rxDB, "R-DBBAK", CatCred, "严重", t) }),
		mk(CatCred, "R-TESTDATA", "开发测试数据识别", "dev/test 数据外泄特征", "关键词正则", "高",
			func(t string, _ Input) []Hit { return rxHits(rxTest, "R-TESTDATA", CatCred, "高", t) }),

		// ---- 业务经营类（7）----
		mk(CatBiz, "R-PII", "个人隐私识别", "手机号/身份证正则聚集度判定；身份证必须过校验位", "正则+聚集度+校验位", "高",
			func(t string, _ Input) []Hit {
				var out []Hit
				for _, m := range firstSub(rxID, t) {
					if validID(m.s) {
						out = append(out, Hit{RuleID: "R-PII", Category: CatBiz, Level: "高", Snippet: mask(m.s), Start: m.start, End: m.end})
					}
				}
				ph := firstSub(rxPhone, t)
				ctx := len(ph) >= 2 || strings.ContainsAny(t, "机话联") // 手机/电话/联系 语境
				if len(ph) > 0 && ctx {
					out = append(out, Hit{RuleID: "R-PII", Category: CatBiz, Level: "高",
						Snippet: mask(ph[0].s) + "（" + strconv.Itoa(len(ph)) + "个手机号聚集）", Start: ph[0].start, End: ph[0].end})
				}
				return out
			}),
		mk(CatBiz, "R-CONTACT", "通讯录识别", "通讯录文件特征，或 职务+多联系方式 组合", "关键词+组合判定", "高",
			func(t string, _ Input) []Hit {
				out := rxHits(rxContact, "R-CONTACT", CatBiz, "高", t)
				if len(out) == 0 && len(firstSub(rxPhone, t)) >= 2 && strings.ContainsAny(t, "职部经主") {
					out = append(out, Hit{RuleID: "R-CONTACT", Category: CatBiz, Level: "高", Snippet: "职务+多联系方式组合"})
				}
				return out
			}),
		mk(CatBiz, "R-BIZDOC", "经营文档识别", "招投标/方案/纪要/制度/运维文档关键词", "关键词正则", "高",
			func(t string, _ Input) []Hit { return rxHits(rxBizDoc, "R-BIZDOC", CatBiz, "高", t) }),
		mk(CatBiz, "R-META", "元数据识别", "文档元数据暴露作者/机构（docx core.xml、PDF Producer）", "元数据判定", "中",
			func(t string, _ Input) []Hit { return rxHits(rxMeta, "R-META", CatBiz, "中", t) }),
		mk(CatBiz, "R-CUSTOMER", "客户信息识别", "客户名单/客户+证件账户组合；伴随批量证件升级严重", "关键词+组合判定", "高",
			func(t string, _ Input) []Hit {
				out := rxHits(rxCust, "R-CUSTOMER", CatBiz, "高", t)
				if len(out) > 0 && len(firstSub(rxPhone, t))+len(firstSub(rxID, t)) >= 2 {
					out[0].Level = "严重"
				}
				return out
			}),
		mk(CatBiz, "R-FINANCE", "财务报表识别", "财报/审计报表关键词与表结构特征", "关键词正则", "高",
			func(t string, _ Input) []Hit { return rxHits(rxFin, "R-FINANCE", CatBiz, "高", t) }),
	}
}

func mask(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return s
	}
	return string(r[:4]) + "****" + string(r[len(r)-2:])
}

func countDistinct(s string) int {
	set := map[rune]bool{}
	for _, c := range s {
		set[c] = true
	}
	return len(set)
}
