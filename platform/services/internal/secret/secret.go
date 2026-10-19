// 密钥有效性验证（M3-C / FR-CHN-002 / WP-M3-05）。
//
// 编号：FR-CHN-002（新凭据入库即验证；仅上报验证为可用的凭据；误报率 ≤10%）、
// WP-M3-05（密钥有效性）、FR-GPH-004（验证结果回写图谱边，闭合 M3-B 边供给缺口）、
// AX-2 确定性、AX-3 可解释、AX-5 人在环（外呼默认关闭）、NFR-SEC（密钥不落明文）。
//
// 三档判据（先省外呼，再谈外呼）：
//  1. context：占位符/示例路径命中 → invalid（不消耗外呼，最常见假阳性）；
//  2. format：已知前缀（AKIA/LTAI/ghp_/sk_live_/AIza…）形状+长度+字符集；
//     PEM/连接串按规则判；无已知前缀 → doubt（形状不可确证，不是有效）；
//  3. probe：仅 format=ok 且请求方给出显式目标且已装配 provider 时才外呼（GET，非破坏）；
//     2xx=valid、401/403=revoked、404=invalid、其余/超时=unverifiable（不可达≠有效≠无效）。
//
// 诚实边界：无 provider=全部 unverifiable（不把「看起来像」当「可用」上报）；
// 端点侧未装配→501 secret_unavailable。密钥原文不落响应、不落图（仅脱敏形态与位置）。
package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// 规则码（与 classify 22 条规则同源）。
const (
	RuleKey      = "R-KEY"
	RulePrivKey  = "R-PRIVKEY"
	RuleConnStr  = "R-CONNSTR"
	RuleHardcode = "R-HARDCODE"
)

// 格式判定与状态判定（枚举固定，端点与度量共用）。
const (
	FormatOK      = "ok"
	FormatDoubt   = "doubt"
	FormatInvalid = "invalid"

	StatusValid        = "valid"
	StatusRevoked      = "revoked"
	StatusInvalid      = "invalid"
	StatusUnverifiable = "unverifiable"

	MethodContext = "context"
	MethodFormat  = "format"
	MethodProbe   = "probe"
)

// 图谱属性键前缀（与图谱其它属性键区分；度量读回同键）。
const (
	propStatus      = "secret_status"
	propMethod      = "secret_method"
	propRule        = "secret_rule"
	propLocation    = "secret_location"
	propMasked      = "secret_masked"
	propEvidence    = "secret_evidence"
	propSource      = "secret_source"
	propProbed      = "secret_probed"
	propProbeStatus = "secret_probe_status"
	propEntropy     = "secret_entropy"
)

// ErrNoGraph 度量/边供给需要图谱；未装配即不可用（不静默退化成「只算不记」）。
var ErrNoGraph = errors.New("secret: 图谱未装配（度量与边供给不可用）")

// knownPrefix 已知密钥形状（前缀 + 长度区间 + 字符集）。
type knownPrefix struct {
	Prefix string
	Min    int
	Max    int
	Label  string
}

// known 顺序固定（长前缀优先匹配，如 sk_live_ 先于 sk-）。
var known = []knownPrefix{
	{"sk_live_", 32, 108, "Stripe 私钥"},
	{"xoxb-", 24, 72, "Slack Bot Token"},
	{"xoxp-", 24, 72, "Slack User Token"},
	{"xoxa-", 24, 72, "Slack App Token"},
	{"AKIA", 20, 20, "AWS Access Key ID"},
	{"LTAI", 24, 32, "阿里云 AccessKey ID"},
	{"AKID", 32, 48, "腾讯云 SecretId"},
	{"AIza", 39, 39, "Google API Key"},
	{"ghp_", 40, 40, "GitHub Personal Token"},
	{"gho_", 40, 40, "GitHub OAuth Token"},
	{"ghu_", 40, 40, "GitHub User Token"},
	{"ghs_", 40, 40, "GitHub Server Token"},
	{"ghr_", 40, 76, "GitHub Refresh Token"},
	{"sk-", 40, 64, "OpenAI API Key"},
}

var (
	rxBody    = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]+$`)
	rxPlace   = regexp.MustCompile(`(?i)^(changeme|change_me|your[_-]?key[_-]?here|your[_-]?secret|placeholder|example[_-]?key|xxxx+|x{4,}|\*+|redacted|dummy|fake[_-]?key|todo|test[_-]?key|abcd1234|123456|password|secret|token)$`)
	rxTestP   = regexp.MustCompile(`(?i)(^|/)(testdata|fixtures?|examples?|samples?|mocks?|demo|spec|test)(/|_)|_test\.|\.test\.|/test/`)
	rxPEM     = regexp.MustCompile(`(?i)BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY`)
	rxConnStr = regexp.MustCompile(`(?i)(password|pwd|user|uid)=[^&\s]{1,}`)
)

// Entry 一次验证输入（密钥原文不入平台：仅位置 + 脱敏形态 + 可选原文片段）。
type Entry struct {
	Tenant      string  `json:"-"`
	Rule        string  `json:"rule"`
	Location    string  `json:"location"`
	Masked      string  `json:"masked,omitempty"`
	Snippet     string  `json:"snippet,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	SourceFP    string  `json:"source_fp,omitempty"`
	ProbeURL    string  `json:"probe_url,omitempty"`
	EvidenceRef string  `json:"evidence_ref,omitempty"`
}

// Verdict 一条验证结论（可复核：形状/状态/方法/依据/证据引用）。
type Verdict struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`
	Location    string   `json:"location"`
	Masked      string   `json:"masked"`
	Format      string   `json:"format"`
	Status      string   `json:"status"`
	Method      string   `json:"method"`
	Reasons     []string `json:"reasons"`
	Entropy     float64  `json:"entropy"`
	SourceFP    string   `json:"source_fp"`
	EvidenceRef string   `json:"evidence_ref"`
	Probed      bool     `json:"probed"`
	ProbeStatus int      `json:"probe_status"`
	Graphed     bool     `json:"graphed"` // 已入图（度量分母）
	Linked      bool     `json:"linked"`  // 已连攻击路径边（仅验证为可用）
}

// Metrics 误报率度量基线（FR-CHN-002 可度量）。
type Metrics struct {
	Tenant           string         `json:"tenant"`
	Total            int            `json:"total"`
	ByStatus         map[string]int `json:"by_status"`
	ByMethod         map[string]int `json:"by_method"`
	Probed           int            `json:"probed"`
	ProbeConfirmed   int            `json:"probe_confirmed"`
	ValidRate        float64        `json:"valid_rate"`
	FPRate           float64        `json:"fp_rate"`
	RevokedRate      float64        `json:"revoked_rate"`
	UnverifiableRate float64        `json:"unverifiable_rate"`
	Basis            string         `json:"basis"`
}

// ProbeResult 外呼结果（Reached=false=未取得状态码，如超时/网络错）。
type ProbeResult struct {
	Reached bool   `json:"reached"`
	Status  int    `json:"status"`
	Err     string `json:"err,omitempty"`
}

// Prober 外呼验证 provider 端口（HTTP 实现在本包；未装配即不外呼）。
type Prober interface {
	Probe(ctx context.Context, e Entry) (ProbeResult, error)
}

// Graph 图谱端口（落 Credential 实体 + 边 + 度量读回；*graph.Service 满足）。
type Graph interface {
	UpsertEntity(ctx context.Context, e graph.Entity) (graph.Entity, bool, error)
	UpsertRelation(ctx context.Context, rel graph.Relation) error
	Entities(ctx context.Context, tenant string) ([]graph.Entity, error)
}

type Service struct {
	prober Prober
	gw     Graph
}

func New() *Service { return &Service{} }

// WithProber 装配外呼 provider（nil/未调用=不外呼，判定为 unverifiable）。
func (s *Service) WithProber(p Prober) *Service {
	s.prober = p
	return s
}

// WithGraph 装配图谱（度量与边供给的落点；未装配=端点 501）。
func (s *Service) WithGraph(g Graph) *Service {
	s.gw = g
	return s
}

// Ready 图谱已装配（端点据此 501，不半可用）。
func (s *Service) Ready() bool { return s.gw != nil }

// ProbeEnabled 外呼 provider 已装配（响应体如实标注，不让人误以为已做过外呼）。
func (s *Service) ProbeEnabled() bool { return s.prober != nil }

// Verify 批量验证：逐条判定 → 入图（分母）→ 仅可用凭据连边。
func (s *Service) Verify(ctx context.Context, tenant string, entries []Entry) ([]Verdict, error) {
	if s.gw == nil {
		return nil, ErrNoGraph
	}
	srcKinds := map[string]bool{}
	if ents, err := s.gw.Entities(ctx, tenant); err == nil {
		for _, e := range ents {
			srcKinds[e.Fingerprint] = true
		}
	} else {
		return nil, fmt.Errorf("secret: 源实体读取失败: %w", err)
	}
	// 结果按输入顺序直出（确定性：不做 map 遍历）
	out := make([]Verdict, 0, len(entries))
	for _, e := range entries {
		e.Tenant = tenant
		v := s.evaluate(ctx, e)
		// 入图：全部判定落 Credential（度量分母）；仅可用凭据连边（FR-CHN-002 仅上报可用）
		if err := s.persistAndMark(ctx, e, &v, srcKinds); err != nil {
			return nil, err
		}
		v.Graphed = true
		out = append(out, v)
	}
	return out, nil
}

// Metrics 从图谱读回判定分布（跨重启保留=对外度量不随进程蒸发）。
func (s *Service) Metrics(ctx context.Context, tenant string) (Metrics, error) {
	if s.gw == nil {
		return Metrics{}, ErrNoGraph
	}
	ents, err := s.gw.Entities(ctx, tenant)
	if err != nil {
		return Metrics{}, fmt.Errorf("secret: 度量读取失败: %w", err)
	}
	m := Metrics{Tenant: tenant, ByStatus: map[string]int{}, ByMethod: map[string]int{}}
	for _, e := range ents {
		if e.Kind != graph.KindCredential {
			continue
		}
		st := e.Props[propStatus]
		if st == "" {
			continue
		}
		m.Total++
		m.ByStatus[st]++
		m.ByMethod[e.Props[propMethod]]++
		if e.Props[propProbed] == "1" {
			m.Probed++
			if st == StatusValid {
				m.ProbeConfirmed++
			}
		}
	}
	if m.Total > 0 {
		den := float64(m.Total)
		m.ValidRate = float64(m.ByStatus[StatusValid]) / den
		m.FPRate = float64(m.ByStatus[StatusInvalid]) / den
		m.RevokedRate = float64(m.ByStatus[StatusRevoked]) / den
		m.UnverifiableRate = float64(m.ByStatus[StatusUnverifiable]) / den
	}
	m.Basis = "分母=本租户全部密钥判定（FR-CHN-002 误报率 ≤10% 的度量基线）；" +
		"fp_rate=invalid/总数（保守口径：unverifiable 既不计误报也不计有效，单列 unverifiable_rate）；" +
		"仅 valid 的凭据连接攻击路径边（上报面只认可用凭据）"
	return m, nil
}

// evaluate 单条判定（格式 → 上下文 → 探活）。
func (s *Service) evaluate(ctx context.Context, e Entry) Verdict {
	v := Verdict{
		ID:          verID(e),
		Rule:        e.Rule,
		Location:    e.Location,
		Masked:      e.Masked,
		Entropy:     e.Entropy,
		SourceFP:    e.SourceFP,
		EvidenceRef: e.EvidenceRef,
	}
	if v.Masked == "" {
		v.Masked = maskOf(e.Snippet)
	}
	snippet := strings.TrimSpace(e.Snippet)
	// ① 格式（形状判定，先算：上下文命中也要留形状信息）
	v.Format, v.Reasons = checkFormat(e.Rule, snippet, v.Reasons)
	// ② 上下文（最强否定：占位符/示例路径），先于探活省外呼
	if neg, ok := checkContext(e.Location, snippet); ok {
		v.Status, v.Method = StatusInvalid, MethodContext
		v.Reasons = append(v.Reasons, neg)
		return v
	}
	// ③ 状态：格式不通过即无效（形状都不对，无需外呼）
	if v.Format == FormatInvalid {
		v.Status, v.Method = StatusInvalid, MethodFormat
		return v
	}
	if v.Format == FormatDoubt {
		v.Status, v.Method = StatusUnverifiable, MethodFormat
		v.Reasons = append(v.Reasons, "无已知形状且未外呼验证，形状不可确证（不作有效上报）")
		return v
	}
	// ④ 探活（需显式目标 + 已装配 provider；两者缺一=不可验证，不是有效）
	if s.prober == nil || strings.TrimSpace(e.ProbeURL) == "" {
		v.Status, v.Method = StatusUnverifiable, MethodFormat
		v.Reasons = append(v.Reasons, "未装配外呼验证或请求方未提供验证目标——不作有效上报")
		return v
	}
	res, err := s.prober.Probe(ctx, e)
	v.Probed = true
	if err != nil {
		v.Status, v.Method = StatusUnverifiable, MethodProbe
		v.Reasons = append(v.Reasons, "外呼失败："+err.Error())
		return v
	}
	v.Method = MethodProbe
	switch {
	case !res.Reached:
		v.ProbeStatus = 0
		v.Status = StatusUnverifiable
		v.Reasons = append(v.Reasons, "外呼未取得响应（超时/网络不可达）：不判定有效也不判定无效")
	case res.Status >= 200 && res.Status < 300:
		v.ProbeStatus = res.Status
		v.Status = StatusValid
		v.Reasons = append(v.Reasons, fmt.Sprintf("外呼 %d：凭据可用", res.Status))
	case res.Status == 401 || res.Status == 403:
		v.ProbeStatus = res.Status
		v.Status = StatusRevoked
		v.Reasons = append(v.Reasons, fmt.Sprintf("外呼 %d：凭据存在但已失效/被拒", res.Status))
	case res.Status == 404:
		v.ProbeStatus = res.Status
		v.Status = StatusInvalid
		v.Reasons = append(v.Reasons, "外呼 404：目标端点不存在，凭据不可用")
	default:
		v.ProbeStatus = res.Status
		v.Status = StatusUnverifiable
		v.Reasons = append(v.Reasons, fmt.Sprintf("外呼 %d：结局不可判定", res.Status))
	}
	return v
}

// persist 落图：Credential 实体（度量分母）+ 仅可用凭据连 leaks 边。
func (s *Service) persist(ctx context.Context, e Entry, v Verdict, srcExists map[string]bool) error {
	props := map[string]string{
		"type":          e.Rule,
		"value":         v.Masked,
		propStatus:      v.Status,
		propMethod:      v.Method,
		propRule:        e.Rule,
		propLocation:    e.Location,
		propMasked:      v.Masked,
		propEvidence:    e.EvidenceRef,
		propSource:      e.SourceFP,
		propEntropy:     fmtFloat(e.Entropy),
		propProbeStatus: strconv.Itoa(v.ProbeStatus),
	}
	if v.Probed {
		props[propProbed] = "1"
	}
	cred := graph.Entity{
		Kind:        graph.KindCredential,
		Tenant:      e.Tenant,
		Fingerprint: graph.Fingerprint(graph.KindCredential, props),
		Props:       props,
		InScope:     true,
		Sources:     []string{"secret:verify"},
	}
	if _, _, err := s.gw.UpsertEntity(ctx, cred); err != nil {
		return fmt.Errorf("secret: 凭据入图失败: %w", err)
	}
	// 仅验证为可用才连边（FR-CHN-002：仅上报可用凭据；不编造不可处置的攻击路径）
	if v.Status != StatusValid || strings.TrimSpace(e.SourceFP) == "" {
		return nil
	}
	if !srcExists[e.SourceFP] {
		return nil // 源不在图内：不伪造来源（宁可不连边）
	}
	rel := graph.Relation{
		Tenant:      e.Tenant,
		Type:        graph.RelLeaks,
		FromFP:      e.SourceFP,
		ToFP:        cred.Fingerprint,
		EvidenceRef: e.EvidenceRef,
	}
	if err := s.gw.UpsertRelation(ctx, rel); err != nil {
		return fmt.Errorf("secret: 泄露边写入失败: %w", err)
	}
	return nil
}

// persistAndMark 落图并在调用侧回填 Linked（persist 内为值拷贝，改不到调用方）。
func (s *Service) persistAndMark(ctx context.Context, e Entry, v *Verdict, src map[string]bool) error {
	if err := s.persist(ctx, e, *v, src); err != nil {
		return err
	}
	if v.Status == StatusValid && strings.TrimSpace(e.SourceFP) != "" && src[e.SourceFP] {
		v.Linked = true
	}
	return nil
}

// checkFormat 形状判定（返回格式与依据）。
func checkFormat(rule, snippet string, reasons []string) (string, []string) {
	s := strings.TrimSpace(snippet)
	if s == "" {
		return FormatDoubt, append(reasons, "无密钥原文片段（gitleaks --redact 不落值），形状不可判定")
	}
	for _, k := range known {
		if strings.HasPrefix(s, k.Prefix) {
			if n := len(s); n < k.Min || n > k.Max {
				return FormatInvalid, append(reasons,
					fmt.Sprintf("前缀 %s 命中但长度 %d 不在 %d~%d（形状不符）", k.Prefix, n, k.Min, k.Max))
			}
			if !rxBody.MatchString(s) {
				return FormatInvalid, append(reasons, "字符集不符（含非法字符）")
			}
			return FormatOK, append(reasons, fmt.Sprintf("前缀 %s 命中且长度 %d 在 %d~%d（形状：%s）",
				k.Prefix, len(s), k.Min, k.Max, k.Label))
		}
	}
	switch rule {
	case RulePrivKey:
		if rxPEM.MatchString(s) {
			return FormatOK, append(reasons, "PEM 私钥头尾完整（形状匹配）")
		}
	case RuleConnStr:
		if strings.Contains(strings.ToLower(s), "jdbc:") && rxConnStr.MatchString(s) {
			return FormatOK, append(reasons, "连接串含 jdbc 与凭据字段（形状匹配）")
		}
	}
	return FormatDoubt, append(reasons, "无已知形状（无已知前缀/无可识别规则形状），形状不可确证")
}

// checkContext 上下文否定（占位符 / 示例测试路径）。
func checkContext(location, snippet string) (string, bool) {
	if loc := strings.TrimSpace(location); loc != "" && rxTestP.MatchString(loc) {
		return "命中位置在示例/测试/夹具路径（假阳性高发），上下文否定", true
	}
	if rxPlace.MatchString(strings.TrimSpace(snippet)) {
		return "取值为占位符/示例值，上下文否定", true
	}
	return "", false
}

// verID 判定 ID（确定性：sha12(租户|规则|位置|脱敏值)）。
func verID(e Entry) string {
	sum := sha256.Sum256([]byte(e.Tenant + "|" + e.Rule + "|" + e.Location + "|" + e.Masked + "|" + e.Snippet))
	return "S-" + hex.EncodeToString(sum[:])[:12]
}

// maskOf 脱敏形态（前 4 + **** + 后 2；与 classify.mask 同口径，短串全掩）。
func maskOf(s string) string {
	v := strings.TrimSpace(s)
	if v == "" {
		return ""
	}
	if len(v) <= 6 {
		return "******"
	}
	return v[:4] + "****" + v[len(v)-2:]
}

func fmtFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// ---- 外呼 provider（默认不装配；装配=显式 env 开启）----

// HTTPProber 非破坏外呼 provider：仅 GET（NFR-SEC-010 非破坏性），带超时与可选步间等待。
type HTTPProber struct {
	client *http.Client
	pacer  Pacer
}

// Pacer 步间等待端口（消费授权 rate_limit；nil=不限速）。
type Pacer interface {
	Wait(ctx context.Context) error
}

// NewHTTPProber 构造外呼 provider（timeout 为单次请求上限）。
func NewHTTPProber(timeout time.Duration, pacer Pacer) *HTTPProber {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &HTTPProber{client: &http.Client{Timeout: timeout, CheckRedirect: noRedirect}, pacer: pacer}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Probe 对请求方显式给出的目标发起 GET（不跟随重定向，避免被带到非预期端点）。
func (p *HTTPProber) Probe(ctx context.Context, e Entry) (ProbeResult, error) {
	target := strings.TrimSpace(e.ProbeURL)
	if target == "" {
		return ProbeResult{}, errors.New("未提供验证目标")
	}
	if p.pacer != nil {
		if err := p.pacer.Wait(ctx); err != nil {
			return ProbeResult{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	req.Header.Set("User-Agent", "easm-secret-probe/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return ProbeResult{Reached: false, Err: err.Error()}, err
	}
	defer resp.Body.Close()
	return ProbeResult{Reached: true, Status: resp.StatusCode}, nil
}
