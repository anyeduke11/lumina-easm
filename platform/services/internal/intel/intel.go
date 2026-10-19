// Package intel 实现情报库（FR-INT-001~003 / F9.3~F9.4）：
// 六类 IOC、CSV/JSON 导入按值去重、资产命中匹配（根域出现在资产名 或 标签相交）。
package intel

import (
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

var (
	ErrHeader = errors.New("intel: csv header mismatch (type,value,threat,family,confidence,source)")
	ErrType   = errors.New("intel: invalid ioc type (六类: domain/ip/url/md5/sha256/email)")
)

var types = map[string]bool{"domain": true, "ip": true, "url": true, "md5": true, "sha256": true, "email": true}

type Entry struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Threat     string   `json:"threat"`
	Family     string   `json:"family,omitempty"`
	Confidence float64  `json:"confidence"`
	Source     string   `json:"source"`
	Tags       []string `json:"tags,omitempty"`
	RootDomain string   `json:"root_domain,omitempty"`
}

type Hit struct {
	AssetID string `json:"asset_id"`
	IOC     Entry  `json:"ioc"`
	Rule    string `json:"rule"` // 界面脚注口径（FR-INT-002）
}

// Key 去重口径唯一入口（FR-INT-003）：type|lower(value)；持久层与内存共用（C-6）。
func Key(e Entry) string { return e.Type + "|" + strings.ToLower(strings.TrimSpace(e.Value)) }

// Store 情报库持久化端口（005_knowledge.sql intel_entries；已存在的 key 不覆盖）。
type Store interface {
	SaveIntel(Entry) error
	LoadIntel() ([]Entry, error)
}

type Service struct {
	mu    sync.RWMutex
	m     map[string]Entry // key = Key()（FR-INT-003 按 IOC 值去重）
	store Store            // nil=纯内存（测试/无 PG 环境）
}

func NewService() *Service {
	s := &Service{m: map[string]Entry{}}
	for _, e := range seed() {
		s.put(e)
	}
	return s
}

// AttachStore 接上持久层：seed 全量写穿（幂等）→ DB 真源 hydrate（root_domain 派生字段重建）。
func (s *Service) AttachStore(st Store) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = st
	for _, e := range s.m {
		if err := st.SaveIntel(e); err != nil {
			return err
		}
	}
	rows, err := st.LoadIntel()
	if err != nil {
		return err
	}
	for _, e := range rows {
		s.put(e)
	}
	return nil
}

func (s *Service) put(e Entry) {
	if e.Type == "domain" && e.RootDomain == "" {
		e.RootDomain = RootDomain(e.Value)
	}
	s.m[Key(e)] = e
}

func (s *Service) ImportCSV(data string) (inserted, skipped int, err error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 || len(rows[0]) < 6 ||
		strings.TrimSpace(rows[0][0]) != "type" || strings.TrimSpace(rows[0][1]) != "value" ||
		strings.TrimSpace(rows[0][5]) != "source" {
		return 0, 0, ErrHeader
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows[1:] {
		if len(row) < 6 || !types[strings.TrimSpace(row[0])] || strings.TrimSpace(row[1]) == "" {
			continue
		}
		key := row[0] + "|" + strings.ToLower(strings.TrimSpace(row[1]))
		if _, dup := s.m[key]; dup {
			skipped++
			continue
		}
		conf, _ := strconv.ParseFloat(strings.TrimSpace(row[4]), 64)
		e := Entry{Type: row[0], Value: strings.TrimSpace(row[1]), Threat: strings.TrimSpace(row[2]),
			Family: strings.TrimSpace(row[3]), Confidence: conf, Source: strings.TrimSpace(row[5])}
		if s.store != nil { // 写穿先行：失败即报错，不留幽灵条目
			if err := s.store.SaveIntel(e); err != nil {
				return inserted, skipped, err
			}
		}
		s.put(e)
		inserted++
	}
	return inserted, skipped, nil
}

func (s *Service) ImportJSON(items []Entry) (inserted, skipped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range items {
		if !types[e.Type] {
			return inserted, skipped, ErrType
		}
		if strings.TrimSpace(e.Value) == "" {
			continue
		}
		if _, dup := s.m[Key(e)]; dup {
			skipped++
			continue
		}
		if s.store != nil {
			if err := s.store.SaveIntel(e); err != nil {
				return inserted, skipped, err
			}
		}
		s.put(e)
		inserted++
	}
	return inserted, skipped, nil
}

func (s *Service) List(typ, family string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.m))
	for _, e := range s.m {
		if typ != "" && e.Type != typ {
			continue
		}
		if family != "" && e.Family != family {
			continue
		}
		out = append(out, e)
	}
	return out
}

// HitAssets 匹配两规则（FR-INT-002，脚注同口径）：
// ① IOC 值或其根域「作为域段」出现在资产名中；② 资产标签与 IOC 标签相交。
func (s *Service) HitAssets(assets []asset.Asset) []Hit {
	entries := s.List("", "")
	var hits []Hit
	for _, a := range assets {
		an := strings.ToLower(a.Name)
		for _, e := range entries {
			if rule := hitRule(e, an, a.Tags); rule != "" {
				hits = append(hits, Hit{AssetID: a.ID, IOC: e, Rule: rule})
			}
		}
	}
	return hits
}

func hitRule(e Entry, assetNameLower string, assetTags []string) string {
	v := strings.ToLower(e.Value)
	switch e.Type {
	case "domain":
		if domainSegmentMatch(assetNameLower, v) || (e.RootDomain != "" && domainSegmentMatch(assetNameLower, strings.ToLower(e.RootDomain))) {
			return "IOC 值/根域出现在资产名中（域段匹配）"
		}
	case "url":
		if host := hostOf(v); host != "" && domainSegmentMatch(assetNameLower, host) {
			return "URL 主机域段匹配"
		}
	case "ip":
		if strings.Contains(assetNameLower, v) {
			return "IP 出现在资产信息中"
		}
	default: // md5/sha256/email 以标签关联
	}
	if len(e.Tags) > 0 && intersect(e.Tags, assetTags) {
		return "标签相交"
	}
	return ""
}

// domainSegmentMatch：needle 必须是 haystack 的完整域名后缀段（evil.com ∌ evilcompany.cn）。
func domainSegmentMatch(haystack, needle string) bool {
	if needle == "" || haystack == "" {
		return false
	}
	if haystack == needle || strings.HasSuffix(haystack, "."+needle) {
		return true
	}
	// 资产名带路径/端口时取主机部分
	if i := strings.IndexAny(haystack, "/:"); i >= 0 {
		h := haystack[:i]
		return h == needle || strings.HasSuffix(h, "."+needle)
	}
	return false
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return u
}

func intersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

// RootDomain 简化口径：取末两段（MVP；公共后缀表在 ENH-08 数据源接入时完善）。
func RootDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if j := strings.IndexAny(host, "/:"); j >= 0 {
		host = host[:j]
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func seed() []Entry {
	raw := [][6]string{
		{"domain", "mal-c2.tracker.ru", "c2", "Mirai", "0.95", "open-source"},
		{"domain", "phish-bank.top", "phishing", "EvilProxy", "0.9", "open-source"},
		{"ip", "185.220.101.7", "scanner", "Mirai", "0.92", "community"},
		{"ip", "45.155.205.233", "exploit", "Log4Shell", "0.88", "community"},
		{"url", "http://185.220.101.7/gate.php", "webshell", "C99", "0.85", "sandbox"},
		{"url", "https://phish-bank.top/login", "phishing", "EvilProxy", "0.9", "sandbox"},
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", "webshell", "Behinder", "0.8", "forensics"},
		{"md5", "44d88612fea8a8f36de82e1278abb02f", "backdoor", "Xorddos", "0.86", "forensics"},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "miner", "Kinsing", "0.87", "sandbox"},
		{"sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "ransomware", "LockBit", "0.93", "forensics"},
		{"email", "attacker@proton-mail.ru", "targeted-attack", "", "0.75", "darkweb"},
		{"email", "hr-svc@fake-recruit.cn", "recruitment-scam", "", "0.7", "darkweb"},
		{"domain", "exfil-drop.su", "exfiltration", "Rclone", "0.84", "darkweb"},
		{"ip", "193.32.162.30", "darkweb-market", "", "0.78", "darkweb"},
		{"domain", "stealer-panel.click", "infostealer", "RedLine", "0.91", "open-source"},
	}
	out := make([]Entry, 0, len(raw))
	for _, r := range raw {
		e := Entry{Type: r[0], Value: r[1], Threat: r[2], Family: r[3], Source: r[5]}
		e.Confidence, _ = strconv.ParseFloat(r[4], 64)
		// 类型关联标签（标签相交规则的可运营面）
		switch e.Type {
		case "md5", "sha256":
			e.Tags = append(e.Tags, "样本")
		}
		if e.Threat != "" {
			e.Tags = append(e.Tags, strings.ReplaceAll(e.Threat, "-", "_"))
		}
		out = append(out, e)
	}
	return out
}
