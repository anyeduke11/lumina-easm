// Package graph 实现 Exposure Graph 本体：13 类实体、11 类关系、确定性指纹与
// 幂等合并（FR-GPH-001~003 / DR-08/DR-09 / 设计方案 §3.2/§3.4）。
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 实体类型（DR-08，13 类）
const (
	KindOrganization  = "Organization"
	KindDomain        = "Domain"
	KindIPBlock       = "IPBlock"
	KindPort          = "Port"
	KindWebApp        = "WebApp"
	KindTechStack     = "TechStack"
	KindCloudResource = "CloudResource"
	KindCodeRepo      = "CodeRepo"
	KindCredential    = "Credential"
	KindVulnerability = "Vulnerability"
	KindIdentity      = "Identity"
	KindBusinessAsset = "BusinessAsset"
	KindEvidence      = "Evidence"
)

// 关系类型（DR-09，11 类）
const (
	RelOwns       = "owns"
	RelResolvesTo = "resolves_to"
	RelHosts      = "hosts"
	RelServes     = "serves"
	RelUses       = "uses"
	RelAffects    = "affects"
	RelLeaks      = "leaks"
	RelValidOn    = "valid_on"
	RelReachable  = "reachable"
	RelDependsOn  = "depends_on"
	RelObserved   = "observed"
)

var (
	ErrKindUnknown = errors.New("graph: unknown entity kind")
	ErrRelUnknown  = errors.New("graph: unknown relation type")

	validKinds = map[string]bool{
		KindOrganization: true, KindDomain: true, KindIPBlock: true, KindPort: true,
		KindWebApp: true, KindTechStack: true, KindCloudResource: true, KindCodeRepo: true,
		KindCredential: true, KindVulnerability: true, KindIdentity: true,
		KindBusinessAsset: true, KindEvidence: true,
	}
	validRels = map[string]bool{
		RelOwns: true, RelResolvesTo: true, RelHosts: true, RelServes: true, RelUses: true,
		RelAffects: true, RelLeaks: true, RelValidOn: true, RelReachable: true,
		RelDependsOn: true, RelObserved: true,
	}
)

type Entity struct {
	Kind        string
	Tenant      string
	Fingerprint string
	Props       map[string]string
	FirstSeen   time.Time
	LastSeen    time.Time
	InScope     bool
	Sources     []string
}

type Relation struct {
	Tenant      string
	Type        string
	FromFP      string // 起点实体指纹
	ToFP        string // 终点实体指纹
	Props       map[string]string
	EvidenceRef string
	TS          time.Time
}

// NormalizeDomain 小写、去首尾空白与末尾点（FR-GPH-002 的域名归一口径）。
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(d, ".")
}

// NormalizeURL 小写 scheme/host，去 path 末尾斜杠（保留查询串）。
func NormalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String()
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Fingerprint 返回确定性指纹；必需属性缺失时返回 ""（Validate 据此拒绝）。
// 口径（设计方案 §3.4）：域名归一 / IP+端口 / URL 规范化 / 组件三元组 / 凭据哈希 / 证据哈希。
func Fingerprint(kind string, props map[string]string) string {
	get := func(k string) string { return strings.TrimSpace(props[k]) }
	switch kind {
	case KindOrganization, KindBusinessAsset:
		if n := get("name"); n != "" {
			return "org:" + strings.ToLower(n) // BusinessAsset 与 Organization 同用 name 键
		}
	case KindDomain:
		if d := NormalizeDomain(get("value")); d != "" {
			return "dom:" + d
		}
	case KindIPBlock:
		if c := strings.ToLower(get("cidr")); c != "" {
			return "ipb:" + c
		}
	case KindPort:
		ip, pt := get("ip"), get("port")
		if ip != "" && pt != "" {
			return "ip:" + ip + "/tcp/" + pt
		}
	case KindWebApp:
		if u := get("url"); u != "" {
			if n := NormalizeURL(u); n != "" {
				return "web:" + n
			}
			// 非完整 URL（裸主机名/带路径片段）：归一为小写去空白的标识串，
			// 保证台账资产总能可投影（避免"入账成功但图谱失败"的部分失败）。
			return "web:" + strings.ToLower(strings.TrimSpace(u))
		}
	case KindTechStack:
		v, p, ver := strings.ToLower(get("vendor")), strings.ToLower(get("product")), strings.ToLower(get("version"))
		if v != "" && p != "" {
			return "cmp:" + v + "|" + p + "|" + ver
		}
	case KindCloudResource:
		if pr, n := strings.ToLower(get("provider")), get("resource"); pr != "" && n != "" {
			return "cloud:" + pr + "|" + strings.ToLower(n)
		}
	case KindCodeRepo:
		if n := NormalizeURL(strings.TrimSuffix(strings.TrimSpace(get("url")), ".git")); n != "" {
			return "repo:" + n
		}
	case KindCredential:
		if t, v := get("type"), get("value"); v != "" {
			return "cred:" + sha(strings.ToLower(t)+"|"+v)
		}
	case KindVulnerability:
		if c := strings.ToLower(get("cve")); c != "" {
			return "vuln:" + c
		}
	case KindIdentity:
		if e := strings.ToLower(get("email")); e != "" {
			return "idn:" + e
		}
	case KindEvidence:
		if r := get("ref"); r != "" {
			return "evi:" + sha(r)
		}
	}
	return ""
}

// Validate 拒绝未知类型与无法生成指纹的实体（C-6 口径唯一）。
func (e Entity) Validate() error {
	if !validKinds[e.Kind] {
		return fmt.Errorf("%w: %q", ErrKindUnknown, e.Kind)
	}
	if strings.TrimSpace(e.Tenant) == "" {
		return errors.New("graph: tenant required")
	}
	if e.Fingerprint != "" {
		return nil
	}
	if Fingerprint(e.Kind, e.Props) == "" {
		return fmt.Errorf("graph: cannot compute fingerprint for %s (missing props)", e.Kind)
	}
	return nil
}

func unionSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// MergeEntity 是「merge 而非新增」的实现（FR-GPH-002）：
// 保留多来源；first_seen 取更早、last_seen 取更晚；空属性不覆盖已有值；in_scope 取或。
func MergeEntity(cur, in Entity) Entity {
	out := cur
	if out.Props == nil {
		out.Props = map[string]string{}
	}
	for k, v := range in.Props {
		if v != "" {
			out.Props[k] = v
		}
	}
	if out.FirstSeen.IsZero() || (!in.FirstSeen.IsZero() && in.FirstSeen.Before(out.FirstSeen)) {
		out.FirstSeen = in.FirstSeen
	}
	if in.LastSeen.After(out.LastSeen) {
		out.LastSeen = in.LastSeen
	}
	out.Sources = unionSorted(cur.Sources, in.Sources)
	out.InScope = cur.InScope || in.InScope
	return out
}

var (
	ErrNotFound  = errors.New("graph: entity not found")
	ErrEndpoints = errors.New("graph: relation endpoints not found")
)

// Store 是图谱存储端口；实现：Neo4j HTTP（本包）等。
type Store interface {
	FindByFingerprint(ctx context.Context, tenant, fp string) (Entity, bool, error)
	SaveEntity(ctx context.Context, e Entity, created bool) error
	UpsertRelation(ctx context.Context, rel Relation) error
}

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service { return &Service{store: store, now: time.Now} }

// UpsertEntity 幂等 upsert：同指纹走 merge（FR-GPH-003）；返回是否新建。
func (s *Service) UpsertEntity(ctx context.Context, e Entity) (Entity, bool, error) {
	if err := e.Validate(); err != nil {
		return e, false, err
	}
	if e.Fingerprint == "" {
		e.Fingerprint = Fingerprint(e.Kind, e.Props)
	}
	if e.FirstSeen.IsZero() {
		e.FirstSeen = s.now()
	}
	if e.LastSeen.IsZero() || e.LastSeen.Before(e.FirstSeen) {
		e.LastSeen = e.FirstSeen
	}
	cur, ok, err := s.store.FindByFingerprint(ctx, e.Tenant, e.Fingerprint)
	if err != nil {
		return e, false, err
	}
	if ok {
		merged := MergeEntity(cur, e)
		if err := s.store.SaveEntity(ctx, merged, false); err != nil {
			return merged, false, err
		}
		return merged, false, nil
	}
	if err := s.store.SaveEntity(ctx, e, true); err != nil {
		return e, true, err
	}
	return e, true, nil
}

// EntityReader 实体枚举能力（store 可选实现；路径推演 Source 与 M3-C 密钥度量需要）。
// 不满足即上浮报错——不返回空切片冒充「该租户无实体」（C-6 双后端同契约）。
type EntityReader interface {
	Entities(ctx context.Context, tenant string) ([]Entity, error)
}

// Entities 枚举租户实体（store 不支持枚举时 fail loud；消费者据此 501 而非空数据）。
func (s *Service) Entities(ctx context.Context, tenant string) ([]Entity, error) {
	r, ok := s.store.(EntityReader)
	if !ok {
		return nil, fmt.Errorf("graph: store %T 不支持实体枚举", s.store)
	}
	return r.Entities(ctx, tenant)
}

func (s *Service) UpsertRelation(ctx context.Context, rel Relation) error {
	if !validRels[rel.Type] {
		return fmt.Errorf("%w: %q", ErrRelUnknown, rel.Type)
	}
	if rel.Tenant == "" || rel.FromFP == "" || rel.ToFP == "" {
		return errors.New("graph: relation requires tenant/from/to")
	}
	if rel.TS.IsZero() {
		rel.TS = s.now()
	}
	return s.store.UpsertRelation(ctx, rel)
}
