// Package vuln 实现漏洞库（FR-VUL-001~004 / F9.1~F9.2）：
// 导入（CSV/JSON 按 CVE 去重）、优先级公式（CVSS 45% + EPSS 35% + 影响面 20%，可复算）、
// 影响资产按标签交集匹配（FR-VUL-002）。
package vuln

import (
	"encoding/csv"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

var ErrHeader = errors.New("vuln: csv header mismatch (cve,title,cvss,epss,severity,category,tags)")

type Entry struct {
	CVE           string   `json:"cve"`
	Title         string   `json:"title"`
	CVSS          float64  `json:"cvss"`
	EPSS          float64  `json:"epss"`
	Severity      string   `json:"severity"`
	Category      string   `json:"category"`
	Tags          []string `json:"tags"`
	Desc          string   `json:"desc,omitempty"`
	Fix           string   `json:"fix,omitempty"`
	MatchedCnt    int      `json:"matched_assets"`
	PriorityScore float64  `json:"priority"` // 0–100，可复算（FR-VUL-003）
}

// Priority 确定性公式（FR-VUL-003）：CVSS(0–10)×10×45% + EPSS(0–1)×100×35% + 影响面×20%；
// 影响面 = min(100, 匹配资产数×20)。同输入必同输出（可复算验收）。
func Priority(cvss, epss float64, matched int) float64 {
	if cvss < 0 {
		cvss = 0
	}
	if cvss > 10 {
		cvss = 10
	}
	if epss < 0 {
		epss = 0
	}
	if epss > 1 {
		epss = 1
	}
	return round1(cvss*10*0.45 + epss*100*0.35 + float64(minInt(matched*20, 100))*0.20)
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Store 漏洞库持久化端口（005_knowledge.sql vuln_entries；PG 实现见 pgstore.KBStore）。
// 幂等语义与导入一致：已存在的 CVE 不覆盖（先到先得）。
type Store interface {
	SaveVuln(Entry) error
	LoadVulns() ([]Entry, error)
}

type Service struct {
	mu    sync.RWMutex
	m     map[string]Entry
	store Store // nil=纯内存（测试/无 PG 环境）
}

func NewService() *Service {
	s := &Service{m: map[string]Entry{}}
	for _, e := range seed() {
		s.m[e.CVE] = e
	}
	return s
}

// AttachStore 接上持久层：seed 全量写穿（幂等）→ DB 真源 hydrate 回内存（跨重启不丢导入条目）。
func (s *Service) AttachStore(st Store) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = st
	for _, e := range s.m {
		if err := st.SaveVuln(e); err != nil {
			return err
		}
	}
	rows, err := st.LoadVulns()
	if err != nil {
		return err
	}
	for _, e := range rows {
		s.m[e.CVE] = e
	}
	return nil
}

// ImportCSV：表头严格校验（fail loud），按 CVE 去重（FR-VUL-004 / A-04）。
func (s *Service) ImportCSV(data string) (inserted, skipped int, err error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 || len(rows[0]) < 7 ||
		strings.TrimSpace(rows[0][0]) != "cve" || strings.TrimSpace(rows[0][1]) != "title" ||
		strings.TrimSpace(rows[0][6]) != "tags" {
		return 0, 0, ErrHeader
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows[1:] {
		if len(row) < 7 || strings.TrimSpace(row[0]) == "" {
			continue
		}
		cve := strings.TrimSpace(row[0])
		if _, dup := s.m[cve]; dup {
			skipped++
			continue
		}
		cvss, _ := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
		epss, _ := strconv.ParseFloat(strings.TrimSpace(row[3]), 64)
		var tags []string
		for _, t := range strings.Split(row[6], "|") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
		e := Entry{CVE: cve, Title: strings.TrimSpace(row[1]), CVSS: cvss, EPSS: epss,
			Severity: strings.TrimSpace(row[4]), Category: strings.TrimSpace(row[5]), Tags: tags}
		if s.store != nil { // 写穿先行：失败即报错，不留「内存有、库里没有」的幽灵条目
			if err := s.store.SaveVuln(e); err != nil {
				return inserted, skipped, err
			}
		}
		s.m[cve] = e
		inserted++
	}
	return inserted, skipped, nil
}

// ImportJSON 同去重语义；重复计入 skipped（幂等，不报错——A-04）。
func (s *Service) ImportJSON(items []Entry) (inserted, skipped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range items {
		if strings.TrimSpace(e.CVE) == "" {
			continue
		}
		if _, dup := s.m[e.CVE]; dup {
			skipped++
			continue
		}
		if s.store != nil {
			if err := s.store.SaveVuln(e); err != nil {
				return inserted, skipped, err
			}
		}
		s.m[e.CVE] = e
		inserted++
	}
	return inserted, skipped, nil
}

func (s *Service) Get(cve string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[cve]
	return e, ok
}

// RecomputePriority 按当前影响面刷新全部条目的 PriorityScore（可复算：公式唯一入口 Priority()）。
func (s *Service) RecomputePriority(counter func(e Entry) int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		e.MatchedCnt = counter(e)
		e.PriorityScore = Priority(e.CVSS, e.EPSS, e.MatchedCnt)
		s.m[k] = e
	}
}

// List 按优先级降序（同分按 CVE 稳定序）；severity/q 过滤。
func (s *Service) List(sev, q string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.m))
	for _, e := range s.m {
		if sev != "" && e.Severity != sev {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.CVE+" "+e.Title), strings.ToLower(q)) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PriorityScore != out[j].PriorityScore {
			return out[i].PriorityScore > out[j].PriorityScore
		}
		return out[i].CVE < out[j].CVE
	})
	return out
}

// MatchAssets 标签交集（FR-VUL-002；界面脚注同口径）。
func (s *Service) MatchAssets(cve string, assets []asset.Asset) []asset.Asset {
	e, ok := s.Get(cve)
	if !ok {
		return nil
	}
	return MatchAssets(e, assets)
}

func MatchAssets(e Entry, assets []asset.Asset) []asset.Asset {
	var out []asset.Asset
	for _, a := range assets {
		if TagsIntersect(e.Tags, a.Tags) {
			out = append(out, a)
		}
	}
	return out
}

func TagsIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

func seed() []Entry {
	out := []Entry{
		{CVE: "CVE-2026-20201", Title: "Redis 未授权访问", CVSS: 9.8, EPSS: 0.94, Severity: "critical", Category: "cache", Tags: []string{"redis"}},
		{CVE: "CVE-2026-20202", Title: "Confluence 模板注入 RCE", CVSS: 9.8, EPSS: 0.91, Severity: "critical", Category: "web", Tags: []string{"confluence"}},
		{CVE: "CVE-2026-20203", Title: "nginx admin 模块栈溢出", CVSS: 9.1, EPSS: 0.83, Severity: "critical", Category: "middleware", Tags: []string{"nginx"}},
		{CVE: "CVE-2026-20204", Title: "GeoServer OGC 表达式注入", CVSS: 9.8, EPSS: 0.79, Severity: "critical", Category: "gis", Tags: []string{"geoserver"}},
		{CVE: "CVE-2026-20205", Title: "Jenkins CLI 未授权", CVSS: 9.8, EPSS: 0.76, Severity: "critical", Category: "devops", Tags: []string{"jenkins"}},
		{CVE: "CVE-2026-20206", Title: "JumpServer 会话劫持", CVSS: 8.6, EPSS: 0.68, Severity: "high", Category: "ops", Tags: []string{"jumpserver"}},
		{CVE: "CVE-2026-20207", Title: "Druid 监控台未授权", CVSS: 7.5, EPSS: 0.61, Severity: "high", Category: "middleware", Tags: []string{"druid"}},
		{CVE: "CVE-2026-20208", Title: "Tomcat manager 弱口令可写", CVSS: 8.8, EPSS: 0.55, Severity: "high", Category: "middleware", Tags: []string{"tomcat"}},
		{CVE: "CVE-2026-20209", Title: "Harbor 机器人账户提权", CVSS: 8.1, EPSS: 0.44, Severity: "high", Category: "container", Tags: []string{"harbor"}},
		{CVE: "CVE-2026-20210", Title: "Spring actuator env 泄露", CVSS: 7.5, EPSS: 0.42, Severity: "high", Category: "java", Tags: []string{"spring"}},
		{CVE: "CVE-2026-20211", Title: "phpMyAdmin 未授权", CVSS: 7.2, EPSS: 0.37, Severity: "high", Category: "web", Tags: []string{"phpmyadmin"}},
		{CVE: "CVE-2026-20212", Title: "Docker API 2375 暴露", CVSS: 9.8, EPSS: 0.33, Severity: "critical", Category: "container", Tags: []string{"docker"}},
		{CVE: "CVE-2026-20213", Title: "Nacos 配置未授权读取", CVSS: 7.5, EPSS: 0.31, Severity: "high", Category: "middleware", Tags: []string{"nacos"}},
		{CVE: "CVE-2026-20214", Title: "Elasticsearch 脚本执行", CVSS: 8.1, EPSS: 0.26, Severity: "high", Category: "cache", Tags: []string{"elasticsearch"}},
		{CVE: "CVE-2026-20215", Title: "Fastjson 反序列化链", CVSS: 7.5, EPSS: 0.19, Severity: "high", Category: "java", Tags: []string{"fastjson"}},
		{CVE: "CVE-2026-20216", Title: "Zabbix agent 主动检查命令注入", CVSS: 7.2, EPSS: 0.14, Severity: "high", Category: "monitor", Tags: []string{"zabbix"}},
		{CVE: "CVE-2026-20217", Title: "MinIO 控制台默认口令", CVSS: 6.5, EPSS: 0.11, Severity: "medium", Category: "storage", Tags: []string{"minio"}},
		{CVE: "CVE-2026-20218", Title: "Grafana 组织信息泄露", CVSS: 5.3, EPSS: 0.08, Severity: "medium", Category: "monitor", Tags: []string{"grafana"}},
	}
	for i := range out {
		e := &out[i]
		e.Fix = "升级至官方修复版本并收敛暴露面"
		e.Desc = fmt.Sprintf("%s（CVSS %v / EPSS %v）", e.Title, e.CVSS, e.EPSS)
		e.PriorityScore = Priority(e.CVSS, e.EPSS, 0)
	}
	return out
}
