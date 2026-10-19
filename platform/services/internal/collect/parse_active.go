// parse_active.go — P3 主动探测渠道 parser（nmap 7.992 / ffuf 2.3.0 实测 schema）。
// 取证口径：nmap -oG「Ports: port/state/proto//svc///」六段位（第 4 段恒空、服务名
// 第 5 段）与 ffuf results 条目（**2.3.0 无 path 字段**，只 url+input.FUZZ）均照
// /tmp probe 实跑输出映射；凭工具文档记忆写=字段错位（gitleaks v8/v9 教训同型）。
package collect

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
)

// nmapPort grepable Ports 段的 open 端口（ip/port/service）。
type nmapPort struct {
	IP      string
	Port    int
	Proto   string
	Service string
}

// nmapOpenPorts -oG → open 端口清单（closed/filtered 不进=只报有效面，防台账刷屏）。
func nmapOpenPorts(b []byte) ([]nmapPort, error) {
	var out []nmapPort
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Host: ") || !strings.Contains(line, "\tPorts: ") {
			continue // Status 行/注释行/# done 行
		}
		ipField := strings.TrimPrefix(line, "Host: ")
		ip := strings.Fields(ipField)[0] // "127.0.0.1 (localhost)" → ip
		sec := ipField[strings.Index(ipField, "Ports: ")+len("Ports: "):]
		if i := strings.Index(sec, "\t"); i >= 0 {
			sec = sec[:i] // Ports 段后接 Ignore State 等列
		}
		for _, ent := range strings.Split(sec, ", ") {
			ent = strings.TrimSpace(strings.Trim(ent, ","))
			if ent == "" {
				continue
			}
			f := strings.Split(ent, "/")
			if len(f) < 4 || f[1] != "open" {
				continue
			}
			port, err := strconv.Atoi(f[0])
			if err != nil {
				return nil, fmt.Errorf("collect: nmap 端口字段异常 %q: %w", ent, err)
			}
			np := nmapPort{IP: ip, Port: port, Proto: f[2]}
			if len(f) > 4 {
				np.Service = f[4]
			}
			out = append(out, np)
		}
	}
	return out, nil
}

// portCandidate 单 open 端口 → 资产候选（ScanPort 授权细目标过滤后逐口映射；
// ParseNmapGrepable 与执行链共用同一映射体=口径单源）。
func portCandidate(np nmapPort, tenant, ts string) (string, error) {
	value := fmt.Sprintf("%s:%d", np.IP, np.Port)
	svc := np.Service
	if svc == "" {
		svc = "unknown"
	}
	c := candidate.Candidate{
		Kind:     "asset",
		TenantID: tenant,
		SubCode:  "SCAN-1",
		Channel:  "port.scan",
		Asset: &candidate.Asset{
			Type: "port", Value: value, Port: np.Port, Service: svc, State: "in_use",
			Extra: map[string]any{"proto": np.Proto, "host": np.IP},
		},
		Evidence: candidate.Evidence{
			TS:     ts,
			RawRef: "nmap-grepable#" + value,
		},
	}
	j, err := c.JSON()
	return string(j), err
}

// ParseNmapGrepable -oG 产物 → 资产候选 JSONL（kind=asset / SCAN-1 / port.scan）。
// 全量 open 端口都进候选复核面；是否入风险台账由 collect 层高危端口判定决定。
func ParseNmapGrepable(b []byte, tenant, ts string) ([]string, error) {
	ports, err := nmapOpenPorts(b)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(ports))
	for _, np := range ports {
		l, err := portCandidate(np, tenant, ts)
		if err != nil {
			return nil, err
		}
		lines = append(lines, l)
	}
	return lines, nil
}

// highRiskPorts 高危端口表（P3 风险清单「高危端口公网开放」；入账=可整改动作面）。
var highRiskPorts = map[int]string{
	21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 135: "MSRPC", 137: "NetBIOS",
	139: "NetBIOS", 143: "IMAP", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// ffufHit230 对齐 ffuf 2.3.0 实测 results 条目（input/url/status/length/content-type）。
type ffufHit230 struct {
	Input struct {
		FUZZ string `json:"FUZZ"`
	} `json:"input"`
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	ContentType string `json:"content-type"`
	URL         string `json:"url"`
}

// ParseFfufReport ffuf -of json 产物 → 发现候选 JSONL（kind=finding / SCAN-2 /
// dir.brute）。等级随有效性：2xx=内容可直接读取=高；3xx/401/403=入口暴露=中。
func ParseFfufReport(b []byte, tenant, ts string) ([]string, error) {
	var doc struct {
		Results []ffufHit230 `json:"results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("collect: ffuf 报告解析失败: %w", err)
	}
	lines := make([]string, 0, len(doc.Results))
	for _, h := range doc.Results {
		risk := "中"
		if h.Status >= 200 && h.Status < 300 {
			risk = "高"
		}
		c := candidate.Candidate{
			Kind:     "finding",
			TenantID: tenant,
			SubCode:  "SCAN-2",
			Channel:  "dir.brute",
			Asset: &candidate.Asset{
				Type: "web", Value: h.URL, State: "in_use",
				Extra: map[string]any{"keyword": h.Input.FUZZ, "status": h.Status,
					"length": h.Length, "content_type": h.ContentType},
			},
			Finding: &candidate.Finding{
				Title:    fmt.Sprintf("目录暴露：%s（HTTP %d）", h.URL, h.Status),
				Category: "系统架构类",
				Risk:     risk,
				Fix:      "隐藏路径加认证/访问控制，禁止匿名可达",
			},
			Evidence: candidate.Evidence{
				TS:     ts,
				RawRef: fmt.Sprintf("%s#%d", h.URL, h.Status),
			},
		}
		j, err := c.JSON()
		if err != nil {
			return nil, err
		}
		lines = append(lines, string(j))
	}
	return lines, nil
}
