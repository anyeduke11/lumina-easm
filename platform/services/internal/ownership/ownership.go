// Package ownership 实现归属判定（FR-DSC-010 + FR-CHN-005，规则版 / AIL-3 的确定性前身）：
// 十类依据（主域/证书/备案/WHOIS/页脚/IP 网段/反查/关键词共现 + 证书指纹/页面结构哈希/
// 内部命名规则/数据字段特征）输出 归属|疑似|无关 三态，带置信度与依据清单；
// 「无关/疑似不自动入账」由 AdmitOrQueue 强制（PRD R2 / 图谱防污染）。
// 后四类=暗网样本归属路径（样本常无域名/备案线索），比对基准=Fingerprints 租户基线。
package ownership

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	VerdictOwned     = "归属"
	VerdictSuspect   = "疑似"
	VerdictUnrelated = "无关"
)

// ErrQueueNotFound 复核项不存在（含已复核/跨租户不可见——统一口径不泄露存在性，AX-5）。
var ErrQueueNotFound = errors.New("ownership: 复核项不存在")

// Identity 租户身份（判定基准；来源=授权录入与备案信息）。
type Identity struct {
	Tenant  string   `json:"tenant"`
	Org     string   `json:"org"`
	Short   string   `json:"short"`
	Domains []string `json:"domains"`
	CIDRs   []string `json:"cidrs"`
}

// Signals 候选资产信号集（工具采集归一后的字段；缺失即空串/空集）。
type Signals struct {
	CertSubject    string `json:"cert_subject,omitempty"`
	WhoisOrg       string `json:"whois_org,omitempty"`
	ICPSubject     string `json:"icp_subject,omitempty"`
	Footer         string `json:"footer,omitempty"`
	ReverseDNS     string `json:"reverse_dns,omitempty"`
	IP             string `json:"ip,omitempty"`
	KeywordCooccur int    `json:"keyword_cooccur,omitempty"` // 单位关键词在页面中共现次数
	// FR-CHN-005 四类资产指纹观测值（暗网样本侧提取，与 Fingerprints 基线比对）
	CertFingerprint string   `json:"cert_fingerprint,omitempty"` // 样本叶子证书指纹（十六进制，可含 : - 分隔）
	PageStructHash  string   `json:"page_struct_hash,omitempty"` // 页面结构骨架哈希
	SampleNames     []string `json:"sample_names,omitempty"`     // 样本内文件/表/库对象名
	DataFields      []string `json:"data_fields,omitempty"`      // 数据集字段名（表头/列名）
}

// Fingerprints 租户资产指纹基线（FR-CHN-005 比对基准；来源=M1 在册资产采集与内部字典）。
// 按租户登记：甲租户基线不得作为乙租户样本的归属依据（C-6 / 一票否决④延伸）。
type Fingerprints struct {
	CertFPs       []string `json:"cert_fps,omitempty"`       // 在册叶子证书指纹
	PageHashes    []string `json:"page_hashes,omitempty"`    // 在册页面结构哈希
	NamingRules   []string `json:"naming_rules,omitempty"`   // 内部命名规则（大小写不敏感子串，如 hdws_、HDDC-）
	FieldFeatures []string `json:"field_features,omitempty"` // 数据字段特征字典（内部专有名，如 cust_id_no）
}

type Verdict struct {
	Domain     string    `json:"domain"`
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	Reasons    []string  `json:"reasons"` // FR-DSC-010 判定依据至少覆盖六类
	TS         time.Time `json:"ts"`
}

type QueueItem struct {
	Seq     int     `json:"seq"`
	Tenant  string  `json:"tenant"` // V-4：复核项必须带租户（跨租户复核面隔离 + PG 行级闸）
	Domain  string  `json:"domain"`
	Verdict Verdict `json:"verdict"`
}

type Service struct {
	mu      sync.Mutex
	queue   []QueueItem
	seq     int
	now     func() time.Time
	qStore  QueueStore // V-4：复核队列持久化端口（014_review_queue.sql）；nil=纯内存
	fpMu    sync.Mutex
	fps     map[string]Fingerprints // 租户 → FR-CHN-005 指纹基线（Judge 读的内存镜像）
	fpStore FPStore                 // 010 落库端口；nil=纯内存过渡形态（无持久）
}

// QueueStore 人工复核队列持久化端口（V-4 / 014_review_queue.sql；C-6 同契约）。
// Save 幂等：同租户同域重复入队=刷新判决并回置待复核（保留原 seq，复核编号稳定）；
// Resolve 标记已复核并留痕（行保留=复核历史可追溯，不同于内存版的出队即消失）。
type QueueStore interface {
	List(ctx context.Context) ([]QueueItem, error) // 水化：仅待复核项
	Save(ctx context.Context, it QueueItem) (int, error)
	Resolve(ctx context.Context, seq int, toVerdict, reviewer string, ts time.Time) error
}

// AttachQueueStore 装载复核队列持久化端口并从库水化待复核项（启动装配=跨重启队列不丢；
// List 失败上浮拒绝半装配——暗网样本判据与队列必须一致，宁 fail loud 不带空队列运行）。
func (s *Service) AttachQueueStore(ctx context.Context, st QueueStore) error {
	rows, err := st.List(ctx)
	if err != nil {
		return fmt.Errorf("ownership: 复核队列水化失败: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, rows...)
	for _, q := range rows {
		if q.Seq > s.seq {
			s.seq = q.Seq
		}
	}
	s.qStore = st
	return nil
}

// FPStore 指纹基线持久化端口（pgstore 实现，010_darkweb.sql；C-6 同契约、SDK 类型不外泄）。
// Judge 热路径读内存镜像（免每判一跳库）；写穿与水化保证「镜像=库」的判据一致性。
type FPStore interface {
	List(ctx context.Context) (map[string]Fingerprints, error)
	Save(ctx context.Context, tenantID string, fp Fingerprints) error
}

func NewService() *Service {
	return &Service{now: time.Now, fps: map[string]Fingerprints{}}
}

// AttachFPStore 装载持久化端口并从库水化既有基线（启动装配=跨重启判据不丢；
// List 失败上浮拒绝半装配——宁可不带历史判据运行并 fail loud，不带错误镜像运行）。
func (s *Service) AttachFPStore(ctx context.Context, st FPStore) error {
	m, err := st.List(ctx)
	if err != nil {
		return fmt.Errorf("ownership: 指纹基线水化失败: %w", err)
	}
	s.fpMu.Lock()
	defer s.fpMu.Unlock()
	for k, v := range m {
		s.fps[k] = v
	}
	s.fpStore = st
	return nil
}

// SetFingerprints 登记/覆盖租户指纹基线（幂等：同租户重复登记以最后一次为准）。
// 有 store 时先写穿、成功后才更新内存镜像——store 失败=镜像不留脏数据（Judge 的判据
// 必须与库里一致；「只在内存生效、重启即蒸发」的合同性静默不允许）。
func (s *Service) SetFingerprints(ctx context.Context, tenantID string, fp Fingerprints) error {
	s.fpMu.Lock()
	st := s.fpStore
	s.fpMu.Unlock()
	if st != nil {
		if err := st.Save(ctx, tenantID, fp); err != nil {
			return err
		}
	}
	s.fpMu.Lock()
	defer s.fpMu.Unlock()
	s.fps[tenantID] = fp
	return nil
}

// FingerprintsOf 读取租户指纹基线；未登记=ok false（调用方据此判「无基线可比对」）。
func (s *Service) FingerprintsOf(tenantID string) (Fingerprints, bool) {
	s.fpMu.Lock()
	defer s.fpMu.Unlock()
	fp, ok := s.fps[tenantID]
	return fp, ok
}

func (s *Service) Judge(id Identity, domain string, sig Signals) Verdict {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	var v Verdict
	v.Domain = d
	v.TS = s.now().UTC()
	add := func(reason string, verdict string, conf float64) {
		v.Reasons = append(v.Reasons, reason)
		if conf >= v.Confidence {
			v.Verdict, v.Confidence = verdict, conf
		}
	}
	// ① 主域/子域（最强直接信号）
	for _, td := range id.Domains {
		td = strings.ToLower(strings.TrimSuffix(td, "."))
		if td != "" && (d == td || strings.HasSuffix(d, "."+td)) {
			add("域名属主域 "+td+"（DNS 解析链）", VerdictOwned, 0.95)
		}
	}
	// ② IP 落授权网段
	if sig.IP != "" && inCIDRs(sig.IP, id.CIDRs) {
		add("IP "+sig.IP+" 在授权网段内（IP 反查）", VerdictOwned, 0.85)
	}
	// ③ 证书主题
	if m := matchOrgText(sig.CertSubject, id); m != "" {
		add("证书主题含单位名（"+m+"）", VerdictOwned, 0.9)
	} else if strings.Contains(sig.CertSubject, "Let's Encrypt") || sig.CertSubject != "" {
		v.Reasons = append(v.Reasons, "证书主题存在但未匹配单位名")
	}
	// ④ ICP 备案主体
	if m := matchOrgText(sig.ICPSubject, id); m != "" {
		add("ICP 备案主体匹配（"+m+"）", VerdictOwned, 0.9)
	}
	// ⑤ WHOIS 组织：中文匹配=归属；存在但不匹配=疑似（人工复核，防第三方同名/隐私代注）
	if m := matchOrgText(sig.WhoisOrg, id); m != "" {
		add("WHOIS 注册组织匹配（"+m+"）", VerdictOwned, 0.85)
	} else if strings.TrimSpace(sig.WhoisOrg) != "" {
		v.Reasons = append(v.Reasons, "WHOIS 组织存在但未匹配，需人工复核")
		if v.Confidence < 0.5 {
			v.Verdict, v.Confidence = VerdictSuspect, 0.4
		}
	}
	// ⑥ 页脚标识
	if m := matchOrgText(sig.Footer, id); m != "" {
		add("页脚含单位标识（"+m+"）", VerdictOwned, 0.8)
	}
	// ⑦ 反解 DNS
	for _, td := range id.Domains {
		if strings.Contains(strings.ToLower(sig.ReverseDNS), strings.ToLower(td)) {
			add("IP 反解指向主域 "+td, VerdictOwned, 0.75)
		}
	}
	// ⑧ 关键词共现（弱信号 → 疑似）
	if sig.KeywordCooccur >= 2 && v.Verdict != VerdictOwned {
		add(fmt.Sprintf("单位关键词共现 %d 次（弱信号）", sig.KeywordCooccur), VerdictSuspect, 0.5)
	}
	// ⑨~⑫ FR-CHN-005 四类资产指纹（暗网样本归属主路径）：命中=归属，未命中/无基线=疑似（人工复核）。
	// soft 只升不降：已有归属结论不被弱证据翻转（避免「有指纹未命中」把在册资产判回疑似）。
	base, _ := s.FingerprintsOf(id.Tenant)
	soft := func(reason string, conf float64) {
		v.Reasons = append(v.Reasons, reason)
		if v.Verdict != VerdictOwned && conf > v.Confidence {
			v.Verdict, v.Confidence = VerdictSuspect, conf
		}
	}
	if fp := strings.TrimSpace(sig.CertFingerprint); fp != "" {
		switch hit := firstMatch(fp, base.CertFPs, sameFP); {
		case len(base.CertFPs) == 0:
			soft("样本证书指纹无在册基线可比对（基线未登记），需人工复核", 0.45)
		case hit != "":
			add("证书指纹与租户在册证书基线一致（"+hit+"）", VerdictOwned, 0.9)
		default:
			soft("样本证书指纹未命中在册基线，需人工复核", 0.55)
		}
	}
	if h := strings.TrimSpace(sig.PageStructHash); h != "" {
		switch hit := firstMatch(h, base.PageHashes, sameFP); {
		case len(base.PageHashes) == 0:
			soft("样本页面结构哈希无在册基线可比对（基线未登记），需人工复核", 0.45)
		case hit != "":
			add("页面结构哈希与租户在册页面基线一致（"+hit+"）", VerdictOwned, 0.85)
		default:
			soft("样本页面结构哈希未命中在册基线，需人工复核", 0.5)
		}
	}
	if names := nonEmpty(sig.SampleNames); len(names) > 0 {
		hits := nameHits(base.NamingRules, names)
		switch {
		case len(base.NamingRules) == 0:
			soft("样本对象名无内部命名规则基线可比对（基线未登记），需人工复核", 0.4)
		case len(hits) >= 2:
			add(fmt.Sprintf("内部命名规则命中 %d 项（%s）", len(hits), strings.Join(hits, "/")), VerdictOwned, 0.8)
		case len(hits) == 1:
			soft("内部命名规则单命中（"+hits[0]+"，巧合名不足以定归属）", 0.6)
		default:
			v.Reasons = append(v.Reasons, "样本对象名未命中内部命名规则（不单独构成否定）")
		}
	}
	if fields := nonEmpty(sig.DataFields); len(fields) > 0 {
		ov := fieldOverlaps(base.FieldFeatures, fields) // 字段名=标识符精确比对（大小写不敏感），防短名子串误配
		switch {
		case len(base.FieldFeatures) == 0:
			soft("数据集字段无特征基线可比对（基线未登记），需人工复核", 0.4)
		case len(ov) >= 3:
			add(fmt.Sprintf("数据字段特征命中 %d 项（%s）", len(ov), strings.Join(ov, "/")), VerdictOwned, 0.8)
		case len(ov) == 2:
			soft(fmt.Sprintf("数据字段特征命中 2 项（%s），需人工复核", strings.Join(ov, "/")), 0.65)
		case len(ov) == 1:
			soft("数据字段特征单命中（"+ov[0]+"），需人工复核", 0.4)
		default:
			v.Reasons = append(v.Reasons, "数据集字段未命中特征基线（不单独构成否定）")
		}
	}
	if v.Verdict == "" {
		v.Verdict, v.Confidence = VerdictUnrelated, 0.9
		v.Reasons = append(v.Reasons, "无任何归属信号且非主域/网段资产")
	}
	return v
}

// AdmitOrQueue 入账闸门：仅「归属」放行；无关/疑似进人工复核队列（不自动入账，可审计）。
// 返回是否入队；装配了 QueueStore 时序号由库权威分配并写穿（失败上浮=队列锚点丢失不得静默，V-4）。
func (s *Service) AdmitOrQueue(ctx context.Context, tenantID string, v Verdict, domain string) (bool, error) {
	if v.Verdict == VerdictOwned {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	it := QueueItem{Tenant: tenantID, Domain: domain, Verdict: v}
	if s.qStore != nil {
		// 不预分配序号：快照不得携带「内存临时 seq」（否则库内 JSONB 与 seq 列漂移，
		// 水化后序号错乱——实测缺陷，V-4 开发轮捕获并修正）。
		seq, err := s.qStore.Save(ctx, it)
		if err != nil {
			return true, fmt.Errorf("ownership: 复核队列落库失败: %w", err)
		}
		it.Seq = seq
		if seq > s.seq {
			s.seq = seq
		}
		// 内存镜像与库一致：已存在同 seq 项=刷新替换（重复入队不得刷出第二项）
		for i, q := range s.queue {
			if q.Seq == seq {
				s.queue[i] = it
				return true, nil
			}
		}
		s.queue = append(s.queue, it)
		return true, nil
	}
	s.seq++
	it.Seq = s.seq
	s.queue = append(s.queue, it)
	return true, nil
}

func (s *Service) Queue() []QueueItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]QueueItem(nil), s.queue...)
}

// Resolve 人工复核出口：改判决并出队（复核留痕入返回快照）。
// 装配了 QueueStore 时先落库后改内存（库失败=复核动作未生效，fail loud 不得假装成功）。
func (s *Service) Resolve(ctx context.Context, seq int, toVerdict, reviewer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, q := range s.queue {
		if q.Seq == seq {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrQueueNotFound
	}
	if s.qStore != nil {
		if err := s.qStore.Resolve(ctx, seq, toVerdict, reviewer, s.now().UTC()); err != nil {
			return fmt.Errorf("ownership: 复核结果落库失败: %w", err)
		}
	}
	s.queue = append(s.queue[:idx], s.queue[idx+1:]...)
	return nil
}

func matchOrgText(text string, id Identity) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if id.Org != "" && strings.Contains(text, id.Org) {
		return id.Org
	}
	if id.Short != "" && len([]rune(id.Short)) >= 2 && strings.Contains(text, id.Short) {
		return id.Short
	}
	return ""
}

func inCIDRs(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if pre, err := netip.ParsePrefix(c); err == nil && pre.Contains(addr) {
			return true
		}
	}
	return false
}

// ---- FR-CHN-005 指纹比对工具 ----

// normFP 归一化指纹/哈希：小写 + 去 `: - _ 空格` 分隔符（工具输出格式差异不影响比对，
// 如 openssl `AA:BB` 与 nmap `aabb`）。
func normFP(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '_', ' ':
			return -1
		}
		return r
	}, s)
}

func sameFP(a, b string) bool {
	na := normFP(a)
	return na != "" && na == normFP(b)
}

// firstMatch 返回基线中与观测值相等的第一项（原样，供依据清单引用），无匹配返回空串。
func firstMatch(observed string, base []string, eq func(string, string) bool) string {
	for _, b := range base {
		if eq(observed, b) {
			return b
		}
	}
	return ""
}

// nameHits 内部命名规则比对：规则作为对象名的（大小写不敏感）子串即命中，逐规则去重计数。
func nameHits(rules, names []string) []string {
	var hits []string
	for _, r := range rules {
		lr := strings.ToLower(strings.TrimSpace(r))
		if lr == "" {
			continue
		}
		for _, n := range names {
			if strings.Contains(strings.ToLower(n), lr) {
				hits = append(hits, r)
				break
			}
		}
	}
	return hits
}

// fieldOverlaps 数据字段特征比对：字段名为标识符，取大小写不敏感的精确交集（逐基线去重）。
func fieldOverlaps(base, observed []string) []string {
	set := map[string]bool{}
	for _, o := range observed {
		set[strings.ToLower(strings.TrimSpace(o))] = true
	}
	var hits []string
	for _, b := range base {
		lb := strings.ToLower(strings.TrimSpace(b))
		if lb != "" && set[lb] {
			hits = append(hits, b)
		}
	}
	return hits
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
