// Package darkweb 实现暗网兜底与线索链（WP-M2-02 / FR-CHN-005~008）：
// 模拟暗网样本 fixture（真实暗网 feed=软阻塞 G8-03，随采购替换本入口样本源）经
// ①四类归属指纹提取→`ownership.Judge` 比对（FR-CHN-005，首小项已闭合的租户指纹基线在此消费）
// ②量级估算（FR-CHN-006：由 ID 连续性/字段完整度反推区间+置信度，绝不单点）
// ③交易链路还原（FR-CHN-007：按发布者/收款地址/文案模板连通分量聚类）
// ④线索包固化（FR-CHN-008：样本哈希/截图/时间戳/来源四要素+整包 sha256，落证据 WORM）。
// 非归属（疑似/无关）样本一律进 `ownership` 人工复核队列、不入线索包（图谱防污染 / 一票否决④延伸）。
package darkweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// Validator 授权总闸（authz.Service 满足）：暗网样本=被动情报形态，只消费有效期/
// 时间窗总闸 Validate（核查轮口径：CheckTarget/窗口属主动探测面，不作用于被动样本）。
type Validator interface {
	Validate(ctx context.Context, tenant string) error
}

// Ledger 台账写口（ledger.Service 满足；ErrDuplicate 用于重放去重计数）。
type Ledger interface {
	Create(ctx context.Context, p rbac.Principal, reqID string, i ledger.Item) error
}

// Sample 暗网样本（模拟 fixture；被动情报）。字段分三组：归属指纹 / 量级线索 / 链路线索。
type Sample struct {
	ID          string `json:"id"`
	Domain      string `json:"domain,omitempty"`     // 样本关联域/onion 主机（判归属用）
	Marketplace string `json:"marketplace"`          // 来源（市场/forum）
	PostURL     string `json:"post_url"`             // 来源帖 URL
	CapturedAt  string `json:"captured_at"`          // 抓取时间戳（RFC3339，取证时间要素）
	RawText     string `json:"raw_text"`             // 样本原文（哈希+文案模板聚类源）
	Screenshot  []byte `json:"screenshot,omitempty"` // 页面截图原始字节（取证截图要素）

	// FR-CHN-005 四类资产指纹观测值（→ ownership.Signals）
	CertFingerprint string   `json:"cert_fingerprint,omitempty"`
	PageStructHash  string   `json:"page_struct_hash,omitempty"`
	SampleNames     []string `json:"sample_names,omitempty"`
	DataFields      []string `json:"data_fields,omitempty"`

	// FR-CHN-006 量级线索
	SampleRecords int   `json:"sample_records"` // 样本内实际记录条数
	IDMin         int64 `json:"id_min,omitempty"`
	IDMax         int64 `json:"id_max,omitempty"`
	FieldTotal    int   `json:"field_total,omitempty"`  // 表字段总数
	FieldFilled   int   `json:"field_filled,omitempty"` // 有值字段数

	// FR-CHN-007 链路线索
	Publisher  string `json:"publisher,omitempty"`   // 发布者身份/handle
	WalletAddr string `json:"wallet_addr,omitempty"` // 收款地址
	AdTemplate string `json:"ad_template,omitempty"` // 文案模板签名（聚类键）
}

// ScaleEstimate 泄露规模区间（FR-CHN-006：Low/High 必为区间，绝不单点）。
type ScaleEstimate struct {
	Low        int     `json:"low"`
	High       int     `json:"high"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"method"`
}

// Chain 交易链路（FR-CHN-007）：共享发布者/收款/模板的样本连通分量 + 合并依据。
type Chain struct {
	ID       string   `json:"id"`
	Members  []string `json:"members"`
	LinkedBy []string `json:"linked_by"`
	Size     int      `json:"size"`
}

// LeadItem 线索包条目（FR-CHN-008 取证四要素：样本哈希/截图ref/时间戳/来源）。
type LeadItem struct {
	SampleID      string  `json:"sample_id"`
	Source        string  `json:"source"`
	PostURL       string  `json:"post_url"`
	CapturedAt    string  `json:"captured_at"`
	SampleHash    string  `json:"sample_hash"`
	ScreenshotRef string  `json:"screenshot_ref,omitempty"`
	Verdict       string  `json:"verdict"`
	Confidence    float64 `json:"confidence"`
}

// LeadPackage 线索包（可直接用于公安通报的固化结构）。
type LeadPackage struct {
	PackageID   string        `json:"package_id"`
	TenantID    string        `json:"tenant_id"`
	GeneratedAt string        `json:"generated_at"`
	Items       []LeadItem    `json:"items"`
	Chains      []Chain       `json:"chains"`
	Scale       ScaleEstimate `json:"scale"`
	ContentHash string        `json:"content_hash"`
	EvidenceRef string        `json:"evidence_ref,omitempty"`
}

// Result 单次巡检计数（全链可观测评量）。
type Result struct {
	Samples     int           `json:"samples"`
	Owned       int           `json:"owned"`
	Queued      int           `json:"queued_review"`
	Accepted    int           `json:"accepted"`
	Unsupported int           `json:"unsupported"`
	NewLedger   int           `json:"new_ledger"`
	Dup         int           `json:"dup"`
	Chains      int           `json:"chains"`
	Scale       ScaleEstimate `json:"scale"`
	PackageID   string        `json:"package_id,omitempty"`
	ContentHash string        `json:"content_hash,omitempty"`
	EvidenceRef string        `json:"evidence_ref,omitempty"`
}

// ExtractSignals 样本→归属判定四类指纹信号（FR-CHN-005 消费入口，字段一一对应不串位）。
func ExtractSignals(s Sample) ownership.Signals {
	return ownership.Signals{
		CertFingerprint: s.CertFingerprint,
		PageStructHash:  s.PageStructHash,
		SampleNames:     append([]string(nil), s.SampleNames...),
		DataFields:      append([]string(nil), s.DataFields...),
	}
}

// EstimateScale 量级估算（FR-CHN-006）：ID 连续性 / 字段完整度反推区间+置信度。
// 关键约束=「不以单点数字作结论」：任何有记录的估计都保证 High>Low（线索不足时按保守倍率展宽）。
func EstimateScale(s Sample) ScaleEstimate {
	if s.SampleRecords <= 0 {
		return ScaleEstimate{Method: "无样本记录（规模不可估）"}
	}
	R := s.SampleRecords
	span := int64(0)
	if s.IDMax > 0 && s.IDMax >= s.IDMin {
		span = s.IDMax - s.IDMin + 1
	}
	low, high := R, R
	conf, method := 0.5, ""
	switch {
	case span > int64(R):
		// ID 跨度大于样本记录：dump 大概率是大表的分片，上限外推至跨度
		low, high = R, int(span)
		conf = 0.5 + 0.3*float64(R)/float64(span)
		method = fmt.Sprintf("ID 连续性外推（样本 %d 条 / ID 跨度 %d）", R, span)
	case span > 0:
		// 样本几乎铺满 ID 跨度：规模≈跨度..记录数
		low, high = int(math.Min(float64(R), float64(span))), int(math.Max(float64(R), float64(span)))
		conf = 0.8
		method = fmt.Sprintf("ID 跨度与样本记录一致（跨度 %d / 样本 %d）", span, R)
	default:
		// 无 ID 线索：保守倍率区间（仍为区间，绝不单点）
		high = R * 3
		conf = 0.4
		method = fmt.Sprintf("无 ID 结构线索，按分片保守倍率（样本 %d ×3 上界）", R)
	}
	// 字段完整度修正：满→提升，缺→降低，并在依据中留痕
	if s.FieldTotal > 0 {
		comp := float64(s.FieldFilled) / float64(s.FieldTotal)
		conf += 0.2 * (comp - 0.5)
		method = fmt.Sprintf("%s；字段完整度 %d/%d", method, s.FieldFilled, s.FieldTotal)
	}
	// 「不以单点」兜底展宽：任何塌成单点的区间按 ×1.5 保守上界
	if high <= low {
		high = int(math.Ceil(float64(low) * 1.5))
		method += "；无离散上限，按 ×1.5 保守展宽"
	}
	conf = clampF(conf, 0.05, 0.95)
	return ScaleEstimate{Low: low, High: high, Confidence: round2(conf), Method: method}
}

// ClusterChains 交易链路聚类（FR-CHN-007）：共享发布者/收款地址/文案模板任一即同链（并查集连通分量）。
func ClusterChains(samples []Sample) []Chain {
	n := len(samples)
	if n == 0 {
		return nil
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) { parent[find(a)] = find(b) }
	// 按三类属性各自「同值即连」
	link := func(keyOf func(Sample) string) {
		seen := map[string]int{}
		for i, s := range samples {
			k := strings.TrimSpace(keyOf(s))
			if k == "" {
				continue
			}
			if j, ok := seen[k]; ok {
				union(i, j)
			} else {
				seen[k] = i
			}
		}
	}
	link(func(s Sample) string { return s.Publisher })
	link(func(s Sample) string { return s.WalletAddr })
	link(func(s Sample) string { return s.AdTemplate })

	groups := map[int][]int{}
	for i := range samples {
		g := find(i)
		groups[g] = append(groups[g], i)
	}
	chains := make([]Chain, 0, len(groups))
	for _, idxs := range groups {
		var members []string
		attrCount := map[string]int{} // 属性值 → 成员出现次数（≥2 = 促成合并的共享键）
		for _, i := range idxs {
			members = append(members, samples[i].ID)
			for _, v := range []string{samples[i].Publisher, samples[i].WalletAddr, samples[i].AdTemplate} {
				if v = strings.TrimSpace(v); v != "" {
					attrCount[v]++
				}
			}
		}
		sort.Strings(members)
		var linked []string
		for v, c := range attrCount {
			if c >= 2 {
				linked = append(linked, v)
			}
		}
		sort.Strings(linked)
		chains = append(chains, Chain{ID: "chain-" + members[0], Members: members, LinkedBy: linked, Size: len(members)})
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].ID < chains[j].ID })
	return chains
}

// BuildPackageItems 线索包条目（FR-CHN-008）：逐样本固化取证四要素——样本哈希（原文 sha256，
// 可复核）、时间戳（抓取时间）、来源（市场+帖 URL）、截图 ref（有证据后端时）。
// shotRefs/verdicts 由巡检编排注入；无证据后端时截图 ref 留空（不伪造锚点）。
func BuildPackageItems(samples []Sample, shotRefs map[string]string, verdicts map[string]ownership.Verdict) []LeadItem {
	items := make([]LeadItem, 0, len(samples))
	for _, s := range samples {
		v := verdicts[s.ID]
		items = append(items, LeadItem{
			SampleID: s.ID, Source: s.Marketplace, PostURL: s.PostURL, CapturedAt: s.CapturedAt,
			SampleHash: sha256hex([]byte(s.RawText)), ScreenshotRef: shotRefs[s.ID],
			Verdict: v.Verdict, Confidence: v.Confidence,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].SampleID < items[j].SampleID })
	return items
}

// packageScale 整包规模（FR-CHN-006 聚合）：逐链取成员估计包络（max 下界 / max 上界），
// 跨链（不同数据集/卖家）求和——绝不单点。
func packageScale(samples []Sample, chains []Chain) ScaleEstimate {
	est := map[string]ScaleEstimate{}
	for _, s := range samples {
		est[s.ID] = EstimateScale(s)
	}
	if len(chains) == 0 {
		return EstimateScale(samples[0])
	}
	var low, high int
	var confs []float64
	methods := []string{}
	for _, c := range chains {
		clow, chigh := 0, 0
		var ccs []float64
		for _, m := range c.Members {
			e := est[m]
			if e.Low > clow {
				clow = e.Low
			}
			if e.High > chigh {
				chigh = e.High
			}
			ccs = append(ccs, e.Confidence)
		}
		low += clow
		high += chigh
		conf := avg(ccs)
		confs = append(confs, conf)
		methods = append(methods, fmt.Sprintf("链 %s [%d,%d]", c.ID, clow, chigh))
	}
	if high <= low && low > 0 {
		high = int(math.Ceil(float64(low) * 1.5))
	}
	return ScaleEstimate{Low: low, High: high, Confidence: round2(clampF(avg(confs), 0.05, 0.95)),
		Method: fmt.Sprintf("按 %d 条链聚合："+"；"+strings.Join(methods, "；"), len(chains))}
}

// Store 线索包持久化端口（pgstore 实现，010_darkweb.sql lead_packages；C-6 同契约）。
// 语义=WORM 首次：同 package_id 重复 Save 不覆盖（重放不改写已出材料，与证据对象同口径）；
// 读写均按租户隔离（GetPackage 跨租户=NotFound，闸不依赖调用方）。
type Store interface {
	SavePackage(ctx context.Context, pkg LeadPackage) error
	ListPackages(ctx context.Context, tenantID string) ([]LeadPackage, error)
	GetPackage(ctx context.Context, tenantID, packageID string) (LeadPackage, bool, error)
}

type Service struct {
	cands *candidate.Service
	led   Ledger
	az    Validator
	own   *ownership.Service
	ev    evidence.Store // nil=不落证据（测试/无对象存储形态；生产装配必配=线索包不可篡改锚点）
	store Store          // 010 落库端口；nil=内存回退（过渡形态）
	now   func() time.Time

	mu   sync.Mutex
	pkgs map[string]LeadPackage // 无 store 时的内存包集（package_id → pkg）
}

func New(cands *candidate.Service, led Ledger, az Validator, own *ownership.Service, ev evidence.Store) *Service {
	return &Service{cands: cands, led: led, az: az, own: own, ev: ev, now: time.Now, pkgs: map[string]LeadPackage{}}
}

// AttachStore 装载线索包持久化端口（cmd/server PG 模式装配；跨重启通报材料可检索）。
func (s *Service) AttachStore(st Store) { s.store = st }

// ListPackages 按租户列举线索包（store 优先；无 store=内存回退）。
func (s *Service) ListPackages(ctx context.Context, tenant string) ([]LeadPackage, error) {
	if s.store != nil {
		return s.store.ListPackages(ctx, tenant)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []LeadPackage
	for _, p := range s.pkgs {
		if p.TenantID == tenant {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageID < out[j].PackageID })
	return out, nil
}

// GetPackage 按租户+包 ID 取回整包（租户不匹配=NotFound，不泄露他租户材料）。
func (s *Service) GetPackage(ctx context.Context, tenant, packageID string) (LeadPackage, bool, error) {
	if s.store != nil {
		return s.store.GetPackage(ctx, tenant, packageID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pkgs[packageID]
	if !ok || p.TenantID != tenant {
		return LeadPackage{}, false, nil
	}
	return p, true, nil
}

// Inspect 暗网样本巡检全链（闸序：写权限→租户作用域→授权总闸 Validate→归属判定→量级/链路→
// 截图/线索包证据固化〔C-5：证据失败不落无锚点线索包〕→lead 候选摄取→线索台账入账去重）。
func (s *Service) Inspect(ctx context.Context, p rbac.Principal, reqID, tenant string, id ownership.Identity, samples []Sample) (Result, error) {
	var res Result
	if !p.Can(rbac.PermWriteAssets) {
		return res, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		return res, rbac.ErrCrossTenant
	}
	if err := s.az.Validate(ctx, tenant); err != nil { // 无有效授权/窗外=拒巡检
		return res, err
	}
	res.Samples = len(samples)

	var owned []Sample
	verdicts := map[string]ownership.Verdict{}
	shotRefs := map[string]string{}
	for _, sm := range samples {
		dom := strings.TrimSpace(sm.Domain)
		if dom == "" {
			dom = hostOf(sm.PostURL)
		}
		v := s.own.Judge(id, dom, ExtractSignals(sm))
		queued, err := s.own.AdmitOrQueue(ctx, tenant, v, dom) // 疑似/无关→进复核队列，不入线索包（防污染）
		if err != nil {
			return res, err // 复核锚点落库失败=上浮（fail loud）：不得带着「样本消失」继续出包
		}
		if queued {
			res.Queued++
			continue
		}
		owned = append(owned, sm)
		verdicts[sm.ID] = v
		res.Owned++
		if s.ev != nil && len(sm.Screenshot) > 0 { // 截图固化（取证截图要素）
			h := evidence.Hash(sm.Screenshot)
			key := "darkweb/" + tenant + "/shot/" + h[:16] + ".bin"
			ref, err := s.ev.Put(ctx, key, sm.Screenshot)
			if errors.Is(err, evidence.ErrImmutable) {
				ref = s.ev.RefOf(key)
			} else if err != nil {
				return res, fmt.Errorf("darkweb: 截图证据固化失败（线索包不落无锚点条目）: %w", err)
			}
			shotRefs[sm.ID] = ref
		}
	}
	if len(owned) == 0 {
		return res, nil // 全部非归属=合法空包（无候选/无台账/无线索包）
	}

	chains := ClusterChains(owned)
	res.Chains = len(chains)
	res.Scale = packageScale(owned, chains)

	// lead 候选摄取（channel=dark.web / sub_code=DRK-1，走 candidate 行级租户闸）
	lines, err := leadCandidateLines(owned, verdicts, tenant, s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return res, err
	}
	acc, uns, err := s.cands.Ingest(ctx, p, strings.Join(lines, "\n"))
	res.Accepted, res.Unsupported = acc, uns

	// 线索包固化（FR-CHN-008）：整包规范内容 sha256 入包 ID → 同输入重放=同 key→WORM 幂等
	pkg := s.buildPackage(ctx, tenant, owned, verdicts, shotRefs, chains)
	res.PackageID = pkg.PackageID
	res.ContentHash = pkg.ContentHash
	res.EvidenceRef = pkg.EvidenceRef

	// 结构化落库（010）：证据对象=不可篡改字节，库=可检索面；写穿失败=中止巡检
	// （「材料出了但查不到」的半状态静默放行不允许——fail loud 同 C-5 口径）。
	if s.store != nil {
		if err := s.store.SavePackage(ctx, pkg); err != nil {
			return res, fmt.Errorf("darkweb: 线索包落库失败（通报材料不可检索，中止入账）: %w", err)
		}
	} else {
		s.mu.Lock()
		s.pkgs[pkg.PackageID] = pkg // 内存回退：同 package_id 覆盖=重放不重复计
		s.mu.Unlock()
	}

	// 线索台账入账（业务经营类·高；去重键含样本 ID，重扫不翻倍）
	note := ""
	if pkg.EvidenceRef != "" {
		note = "snapshot_ref=" + pkg.EvidenceRef
	}
	for _, sm := range owned {
		it := ledger.Item{
			ID: "L-DRK-" + itemHash(tenant+"|"+sm.ID), Tenant: tenant, Phase: "P4",
			Category: "业务经营类", Asset: sm.PostURL,
			Title: fmt.Sprintf("暗网泄露线索：%s（%s）", sm.ID, sm.Marketplace),
			Level: "高", Source: "DRK-1/dark.web", Found: s.now().UTC(),
			Action: "联系平台依法依规清理", Owner: "安全运营", Due: s.now().UTC().Add(24 * time.Hour),
			Note: note,
		}
		if err := s.led.Create(ctx, p, reqID, it); err != nil {
			if errors.Is(err, ledger.ErrDuplicate) {
				res.Dup++
				continue
			}
			return res, err
		}
		res.NewLedger++
	}
	return res, nil
}

// buildPackage 组装线索包并固化证据：ContentHash 只覆盖稳定取证内容（items/chains/scale），
// 不含 GeneratedAt/EvidenceRef——同输入重放哈希恒定=WORM 幂等复用既有 ref。
func (s *Service) buildPackage(ctx context.Context, tenant string, owned []Sample, verdicts map[string]ownership.Verdict, shotRefs map[string]string, chains []Chain) LeadPackage {
	items := BuildPackageItems(owned, shotRefs, verdicts)
	ids := make([]string, 0, len(owned))
	for _, sm := range owned {
		ids = append(ids, sm.ID)
	}
	sort.Strings(ids)
	pkgID := "LPK-" + itemHash(tenant+"|"+strings.Join(ids, ","))

	content, _ := json.Marshal(struct {
		TenantID string        `json:"tenant_id"`
		Items    []LeadItem    `json:"items"`
		Chains   []Chain       `json:"chains"`
		Scale    ScaleEstimate `json:"scale"`
	}{tenant, items, chains, packageScale(owned, chains)})
	contentHash := sha256hex(content)

	pkg := LeadPackage{
		PackageID: pkgID, TenantID: tenant, GeneratedAt: s.now().UTC().Format(time.RFC3339),
		Items: items, Chains: chains, Scale: packageScale(owned, chains), ContentHash: contentHash,
	}
	if s.ev != nil { // 整包固化（WORM）：线索包本体即证据，ref 可回溯
		pb, _ := json.Marshal(pkg)
		key := "darkweb/" + tenant + "/package/" + pkgID + ".json"
		ref, err := s.ev.Put(ctx, key, pb)
		if errors.Is(err, evidence.ErrImmutable) {
			ref = s.ev.RefOf(key)
		} else if err != nil {
			pkg.EvidenceRef = "" // 整包固化失败=上浮无 ref（item 已含截图锚点，调用方据 EvidenceRef 空判降级）
			return pkg
		}
		pkg.EvidenceRef = ref
	}
	return pkg
}

func leadCandidateLines(samples []Sample, verdicts map[string]ownership.Verdict, tenant, ts string) ([]string, error) {
	lines := make([]string, 0, len(samples))
	for _, sm := range samples {
		v := verdicts[sm.ID]
		c := candidate.Candidate{
			Kind: "lead", TenantID: tenant, SubCode: "DRK-1", Channel: "dark.web",
			Lead: map[string]any{
				"sample_id": sm.ID, "marketplace": sm.Marketplace, "post_url": sm.PostURL,
				"scale_low": EstimateScale(sm).Low, "scale_high": EstimateScale(sm).High,
				"ownership_confidence": v.Confidence,
			},
			Evidence: candidate.Evidence{TS: ts, RawRef: sm.PostURL},
		}
		j, err := c.JSON()
		if err != nil {
			return nil, err
		}
		lines = append(lines, string(j))
	}
	return lines, nil
}

func hostOf(u string) string {
	parsed, err := url.Parse(strings.TrimSpace(u))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func itemHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func clampF(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }

func avg(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// RenderPackageMD 线索包对外导出文本（FR-CHN-007，`leadpackage:export?format=md` 消费）。
// 确定性：同包两次渲染逐字节一致（AX-3 可独立复核）；内容覆盖通报交付四面——
// 归属（包内即归属样本）、量级（FR-CHN-006 区间口径）、链路（FR-CHN-007 连通分量+合并依据）、
// 取证四要素（FR-CHN-008：样本哈希/截图 ref/时间戳/来源）。格式细节与 G8-02 报送交叠处随其定稿。
func RenderPackageMD(pkg LeadPackage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 暗网线索包 %s\n\n", pkg.PackageID)
	fmt.Fprintf(&b, "- 租户: %s\n", pkg.TenantID)
	fmt.Fprintf(&b, "- 生成时间: %s\n", pkg.GeneratedAt)
	fmt.Fprintf(&b, "- 内容哈希: %s\n", pkg.ContentHash)
	if pkg.EvidenceRef != "" {
		fmt.Fprintf(&b, "- 证据引用: %s（经 /v1/evidence 可独立回溯）\n", pkg.EvidenceRef)
	}
	b.WriteString("\n## 泄露规模（区间口径，FR-CHN-006）\n\n")
	if pkg.Scale.Method == "" {
		b.WriteString("- 规模不可估（无样本记录）\n")
	} else {
		fmt.Fprintf(&b, "- 估计区间: %d–%d（置信度 %.2f）\n- 估算方法: %s\n",
			pkg.Scale.Low, pkg.Scale.High, pkg.Scale.Confidence, pkg.Scale.Method)
	}
	b.WriteString("\n## 交易链路（连通分量，FR-CHN-007）\n")
	for _, c := range pkg.Chains {
		fmt.Fprintf(&b, "\n### %s（成员 %d）\n", c.ID, c.Size)
		fmt.Fprintf(&b, "- 合并依据: %s\n", strings.Join(c.LinkedBy, "、"))
		fmt.Fprintf(&b, "- 成员: %s\n", strings.Join(c.Members, ", "))
	}
	b.WriteString("\n## 条目清单与取证四要素（FR-CHN-008）\n")
	for _, it := range pkg.Items {
		fmt.Fprintf(&b, "\n### 样本 %s\n", it.SampleID)
		fmt.Fprintf(&b, "- 来源: %s\n- 链接: %s\n- 捕获时间: %s\n- 样本哈希: %s\n",
			it.Source, it.PostURL, it.CapturedAt, it.SampleHash)
		if it.ScreenshotRef != "" {
			fmt.Fprintf(&b, "- 截图证据: %s\n", it.ScreenshotRef)
		}
		fmt.Fprintf(&b, "- 裁决: %s（置信度 %.2f）\n", it.Verdict, it.Confidence)
	}
	return b.String()
}
