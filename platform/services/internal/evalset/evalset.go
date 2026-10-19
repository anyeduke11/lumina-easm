// Package evalset 评测集与反馈门禁骨架（M3-E / WP-M3-06）。
//
// 编号：FR-VRF-004（误报回流闭环：台账反证/复测结论回流为评测样本）、AIL-7（评测与
// 反馈门禁：指标不达标不放量）、NFR-MNT-005（可维护的确定性评测面）、FR-CLS-001~007
// （首个评测对象=22 规则判敏引擎）、AX-2（确定性）、AX-3（指标可复算）、AX-6（Subject
// 为 Provider 接缝：AI 面经此替换装配，ENH-03，上层零改动）。
//
// 骨架边界（不冒充闭合）：
//   - 评测对象经 Subject 端口注入；当前仅装配确定性判敏引擎（ClassifySubject）。
//     AI 研判面（ENH-03）未接入，评测指标只对已装配对象有意义；
//   - 幻觉率口径=预测为敏/为真的结论中无证据支撑的占比；确定性引擎的命中自带规则
//     编号依据，该指标为其 AI 后继者预留（接缝不变）；
//   - 门禁为机器可读的放量判定（allow/reasons）：指标不达标不放量，无评测记录 fail
//     closed；放量动作本身（AI 面灰度开关）待 ENH-03 装配后消费本判定。
package evalset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// 样本来源与评价对象 kind（骨架仅判敏面，kind 校验拒绝其余=诚实边界）。
const (
	SourceManual = "manual"
	SourceReflux = "reflux"

	KindSens = "sens" // 判敏样本：文本 → 是否敏感（对应 22 规则判敏对象）
)

// ErrNoSamples 空评测集（对空集算 F1 是伪造统计，必须拒绝）。
var ErrNoSamples = errors.New("evalset: 评测集为空，先导入/回流样本再评测")

// ErrSampleNotFound 样本不存在（二次标注指向了别的租户或不存在的 ID）。
var ErrSampleNotFound = errors.New("evalset: 样本不存在")

// ErrInvalid 请求不合法（缺标注人/空文本/未知 kind 等；httpapi 映射 400）。
var ErrInvalid = errors.New("evalset: 非法请求")

// DefaultThresholdSource 默认门禁阈值口径来源（与评分四因子同批：待 G8-01 定稿）。
const DefaultThresholdSource = "default（F1≥0.90/误报≤0.10/κ≥0.60/幻觉≤0/样本≥30；口径待 G8-01 定稿）"

// SampleInput 手工导入样本（回流样本由 Reflux 从台账条目构造）。
type SampleInput struct {
	Kind        string `json:"kind"`
	Text        string `json:"text"`
	Expected    bool   `json:"expected"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	LedgerID    string `json:"ledger_id,omitempty"`
}

// Relabel 二次人工标注（κ=标注一致性需要第二评分者；AIL-7 人在环）。
type Relabel struct {
	By       string    `json:"by"`
	Expected bool      `json:"expected"`
	Note     string    `json:"note,omitempty"`
	TS       time.Time `json:"ts"`
}

// Sample 评测样本（确定性 ID：同租户同文本同期望=同一样本，重放幂等）。
type Sample struct {
	ID          string    `json:"id"`
	Tenant      string    `json:"tenant"`
	Kind        string    `json:"kind"`
	Text        string    `json:"text"`
	Expected    bool      `json:"expected"`
	ExpectedBy  string    `json:"expected_by"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	LedgerID    string    `json:"ledger_id,omitempty"`
	Source      string    `json:"source"`
	Relabels    []Relabel `json:"relabels,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Skip 如实单列（跳过的样本/台账条目不静默丢弃，AX-3）。
type Skip struct {
	SampleID string `json:"sample_id,omitempty"`
	LedgerID string `json:"ledger_id,omitempty"`
	Reason   string `json:"reason"`
}

// Subject 评测对象端口（AX-6 Provider 接缝）：确定性判敏引擎为首个装配；
// AI 研判面（ENH-03）经此替换，评测/门禁上层零改动。evidence=结论依据，
// 阳性结论无依据计入幻觉率（无证据结论占比，评测集验收口径）。
type Subject interface {
	Name() string
	Judge(ctx context.Context, s Sample) (predicted bool, evidence string, err error)
}

// ClassifySubject 判敏引擎评测对象（确定性；命中即敏感，依据=规则编号列表）。
type ClassifySubject struct{ engine *classify.Engine }

// NewClassifySubject 以 22 规则判敏引擎构造首个评测对象。
func NewClassifySubject(e *classify.Engine) ClassifySubject { return ClassifySubject{engine: e} }

func (c ClassifySubject) Name() string { return "classify-22rules" }

func (c ClassifySubject) Judge(_ context.Context, s Sample) (bool, string, error) {
	hits := c.engine.Detect(s.Text, classify.Input{})
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.RuleID)
	}
	if len(ids) == 0 {
		return false, "无命中（0 规则）", nil // 负样本留依据；仅阳性结论无依据才计入幻觉率
	}
	return true, strings.Join(ids, ","), nil
}

// Confusion 混淆矩阵（expected=true 视为正类：敏感）。
type Confusion struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

// Thresholds 放量门禁阈值（全部比率 ∈ [0,1]；MinSamples ≥1）。
type Thresholds struct {
	F1Min            float64 `json:"f1_min"`
	FPRateMax        float64 `json:"fp_rate_max"`
	KappaMin         float64 `json:"kappa_min"`
	HallucinationMax float64 `json:"hallucination_max"`
	MinSamples       int     `json:"min_samples"`
}

// DefaultThresholds 登记口径默认阈值（待 G8-01 定稿，非定稿值）。
func DefaultThresholds() Thresholds {
	return Thresholds{F1Min: 0.90, FPRateMax: 0.10, KappaMin: 0.60, HallucinationMax: 0, MinSamples: 30}
}

// Validate 阈值校验（非法配置一律拒=口径失真不上线）。
func (t Thresholds) Validate() error {
	for _, v := range []float64{t.F1Min, t.FPRateMax, t.KappaMin, t.HallucinationMax} {
		if v < 0 || v > 1 {
			return fmt.Errorf("evalset: 阈值比率须在 [0,1]，实际 %+v", t)
		}
	}
	if t.MinSamples < 1 {
		return fmt.Errorf("evalset: 最小样本数须 ≥1，实际 %d", t.MinSamples)
	}
	return nil
}

// ParseThresholds 解析 "0.90,0.10,0.60,0.00,30"（f1,误报,κ,幻觉,最小样本；配置注入面）。
func ParseThresholds(s string) (Thresholds, error) {
	p := strings.Split(strings.TrimSpace(s), ",")
	if len(p) != 5 {
		return Thresholds{}, fmt.Errorf("evalset: 阈值须为 5 段（f1,误报,κ,幻觉,最小样本），得 %q", s)
	}
	f := make([]float64, 4)
	for i := range f {
		x, err := strconv.ParseFloat(strings.TrimSpace(p[i]), 64)
		if err != nil {
			return Thresholds{}, fmt.Errorf("evalset: 阈值段 %d 非数值: %q", i, p[i])
		}
		f[i] = x
	}
	n, err := strconv.Atoi(strings.TrimSpace(p[4]))
	if err != nil {
		return Thresholds{}, fmt.Errorf("evalset: 最小样本数非整数: %q", p[4])
	}
	th := Thresholds{f[0], f[1], f[2], f[3], n}
	return th, th.Validate()
}

// GateDecision 放量门禁判定（机器可读：指标不达标不放量；原因逐条点名）。
type GateDecision struct {
	Allow        bool       `json:"allow"`
	Reasons      []string   `json:"reasons"`
	Thresholds   Thresholds `json:"thresholds"`
	ThresholdSrc string     `json:"threshold_source"`
	Basis        string     `json:"basis"`
}

// Run 一次评测运行（指标全部由混淆矩阵复算可得=AX-3）。
type Run struct {
	ID                string       `json:"id"`
	Tenant            string       `json:"tenant"`
	Subject           string       `json:"subject"`
	TS                time.Time    `json:"ts"`
	Total             int          `json:"total"` // 实际计入指标样本数（判定失败的单列 Skipped）
	Confusion         Confusion    `json:"confusion"`
	Precision         float64      `json:"precision"`
	Recall            float64      `json:"recall"`
	F1                float64      `json:"f1"`
	Accuracy          float64      `json:"accuracy"`
	FPRate            float64      `json:"fp_rate"`
	HallucinationRate float64      `json:"hallucination_rate"`
	Kappa             *float64     `json:"kappa,omitempty"` // 标注一致性（Cohen κ）；无二次标注=nil
	KappaCover        int          `json:"kappa_cover"`
	Skipped           []Skip       `json:"skipped,omitempty"`
	Gate              GateDecision `json:"gate"`
	Basis             string       `json:"basis"`
}

// Store 持久化接口：内存实现随包提供；PG 实现在 pgstore（双后端同契约，C-6）。
type Store interface {
	PutSample(ctx context.Context, s Sample) (created bool, err error)
	ListSamples(ctx context.Context, tenant string) ([]Sample, error)
	AppendRelabel(ctx context.Context, tenant, sampleID string, rl Relabel) error
	PutRun(ctx context.Context, r Run) error
	ListRuns(ctx context.Context, tenant string, limit int) ([]Run, error)
}

// RefluxResult 回流结果（幂等：重放 added=0；无信号条目单列跳过）。
type RefluxResult struct {
	Added   int      `json:"added"`
	Samples []Sample `json:"samples"`
	Skipped []Skip   `json:"skipped,omitempty"`
}

// Service 评测集与门禁服务（每域 Store 接口 + 内存实现；PG 装配在 main）。
type Service struct {
	store Store
	th    Thresholds
	thSrc string
}

// New 构造服务（默认登记口径阈值；EASM_EVAL_THRESHOLDS 注入走 WithThresholds）。
func New(st Store) *Service {
	return &Service{store: st, th: DefaultThresholds(), thSrc: DefaultThresholdSource}
}

// WithThresholds 注入门禁阈值（非法装载即拒，fail loud）。
func (s *Service) WithThresholds(th Thresholds) *Service {
	if err := th.Validate(); err != nil {
		panic(err.Error()) // 装配期错误：与 scoring 非法配置同口径，拒绝静默降级
	}
	s.th, s.thSrc = th, "env（EASM_EVAL_THRESHOLDS）"
	return s
}

// ThresholdInfo 阈值与口径来源回显。
func (s *Service) ThresholdInfo() (Thresholds, string) { return s.th, s.thSrc }

// AddSamples 手工导入样本（人在环：by 必填；同文本同期望幂等去重）。
func (s *Service) AddSamples(ctx context.Context, tenant string, in []SampleInput, by string) (int, []Sample, error) {
	if strings.TrimSpace(by) == "" {
		return 0, nil, fmt.Errorf("%w: 标注人必填（人在环，标注可追溯）", ErrInvalid)
	}
	now := time.Now().UTC()
	out := make([]Sample, 0, len(in))
	added := 0
	for _, i := range in {
		if strings.TrimSpace(i.Text) == "" {
			return 0, nil, fmt.Errorf("%w: 样本文本不可为空", ErrInvalid)
		}
		if i.Kind != KindSens {
			return 0, nil, fmt.Errorf("%w: 暂不支持的评价对象 kind %q（骨架=判敏面，AI 研判面待 ENH-03）", ErrInvalid, i.Kind)
		}
		sm := Sample{
			ID: sampleID(tenant, i), Tenant: tenant, Kind: i.Kind, Text: i.Text,
			Expected: i.Expected, ExpectedBy: by, EvidenceRef: i.EvidenceRef,
			LedgerID: i.LedgerID, Source: SourceManual, CreatedAt: now,
		}
		created, err := s.store.PutSample(ctx, sm)
		if err != nil {
			return 0, nil, err
		}
		if created {
			added++
		}
		out = append(out, sm)
	}
	return added, out, nil
}

// Samples 列举本租户全部样本。
func (s *Service) Samples(ctx context.Context, tenant string) ([]Sample, error) {
	return s.store.ListSamples(ctx, tenant)
}

// Relabel 追加二次标注（κ 评分者；by 必填）。
func (s *Service) Relabel(ctx context.Context, tenant, sampleID, by string, expected bool, note string) (Sample, error) {
	if strings.TrimSpace(by) == "" {
		return Sample{}, fmt.Errorf("%w: 标注人必填（人在环，标注可追溯）", ErrInvalid)
	}
	rl := Relabel{By: by, Expected: expected, Note: note, TS: time.Now().UTC()}
	if err := s.store.AppendRelabel(ctx, tenant, sampleID, rl); err != nil {
		return Sample{}, err
	}
	return s.getSample(ctx, tenant, sampleID)
}

// getSample 从清单回读（样本量=评测面量级，O(n) 可接受；不引入按 ID 索引的第二份真相）。
func (s *Service) getSample(ctx context.Context, tenant, id string) (Sample, error) {
	ss, err := s.store.ListSamples(ctx, tenant)
	if err != nil {
		return Sample{}, err
	}
	for _, sm := range ss {
		if sm.ID == id {
			return sm, nil
		}
	}
	return Sample{}, ErrSampleNotFound
}

// Reflux 台账结论回流（FR-VRF-004 误报回流闭环）：
//   - 反证成立（Refute confirmed）或最近一次复测 refuted → 误报样本（expected=false）；
//   - 最近一次复测 reproduced（且无更强否定信号）→ 真阳性样本（expected=true）；
//   - 两者并存时以复测（门3）为最终裁决、反证为否定信号：refuted 信号优先（宁缺毋滥，
//     不把存疑结论当真阳性灌入评测集）；reproduced 需无 confirmed 反证才回流；
//   - 无任何信号 → 跳过留痕（不猜标签）。
func (s *Service) Reflux(ctx context.Context, tenant string, items []ledger.Item, by string) (RefluxResult, error) {
	if strings.TrimSpace(by) == "" {
		return RefluxResult{}, fmt.Errorf("%w: 标注人必填（人在环，标注可追溯）", ErrInvalid)
	}
	res := RefluxResult{Samples: []Sample{}}
	for _, it := range items {
		if it.Tenant != tenant {
			res.Skipped = append(res.Skipped, Skip{LedgerID: it.ID, Reason: "跨租户条目拒绝回流"})
			continue
		}
		var expected bool
		var evRef string
		switch classifyReflux(it) {
		case refluxFalse:
			expected, evRef = false, latestVerifEvidence(it, "refuted")
			if evRef == "" {
				evRef = refuteEvidence(it)
			}
		case refluxTrue:
			expected, evRef = true, latestVerifEvidence(it, "reproduced")
		default:
			res.Skipped = append(res.Skipped, Skip{LedgerID: it.ID,
				Reason: "无反证结论/复测记录——无回流信号，不猜标签"})
			continue
		}
		in := SampleInput{Kind: KindSens, Text: it.Title, Expected: expected,
			EvidenceRef: evRef, LedgerID: it.ID}
		sm := Sample{
			ID: sampleID(tenant, in), Tenant: tenant, Kind: KindSens, Text: it.Title,
			Expected: expected, ExpectedBy: by, EvidenceRef: evRef,
			LedgerID: it.ID, Source: SourceReflux, CreatedAt: time.Now().UTC(),
		}
		created, err := s.store.PutSample(ctx, sm)
		if err != nil {
			return RefluxResult{}, err
		}
		if created {
			res.Added++
		}
		res.Samples = append(res.Samples, sm)
	}
	return res, nil
}

const (
	refluxNone  = 0
	refluxFalse = 1
	refluxTrue  = 2
)

// classifyReflux 回流信号判定（refuted 信号优先=宁缺毋滥）。
func classifyReflux(it ledger.Item) int {
	for _, rc := range it.Refute {
		if rc.Outcome == "confirmed" {
			return refluxFalse
		}
	}
	if len(it.Verifs) == 0 {
		return refluxNone
	}
	last := it.Verifs[len(it.Verifs)-1] // Verifs 追加式，最后一条=最近复测
	switch last.Result {
	case ledger.ResultRefuted:
		return refluxFalse
	case ledger.ResultReproduced:
		return refluxTrue
	default:
		return refluxNone
	}
}

func refuteEvidence(it ledger.Item) string {
	for _, rc := range it.Refute {
		if rc.Outcome == "confirmed" {
			return rc.Evidence
		}
	}
	return ""
}

func latestVerifEvidence(it ledger.Item, result string) string {
	if len(it.Verifs) == 0 {
		return ""
	}
	last := it.Verifs[len(it.Verifs)-1]
	if last.Result == result {
		return last.EvidenceRef
	}
	return ""
}

// Run 执行评测：逐样本判定 → 混淆矩阵/指标（可复算）→ 门禁判定 → 落库。
// 判定失败样本单列 Skipped（不静默丢弃、不计入指标）。
func (s *Service) Run(ctx context.Context, tenant string, sub Subject) (Run, error) {
	if sub == nil {
		return Run{}, fmt.Errorf("%w: 评测对象未装配", ErrInvalid)
	}
	samples, err := s.store.ListSamples(ctx, tenant)
	if err != nil {
		return Run{}, err
	}
	if len(samples) == 0 {
		return Run{}, ErrNoSamples
	}
	run := Run{ID: runID(tenant, sub.Name()), Tenant: tenant, Subject: sub.Name(),
		TS: time.Now().UTC(), Skipped: []Skip{}}
	posWithEv, posTotal := 0, 0
	for _, sm := range samples {
		pred, ev, err := sub.Judge(ctx, sm)
		if err != nil {
			run.Skipped = append(run.Skipped, Skip{SampleID: sm.ID, Reason: "判定失败：" + err.Error()})
			continue
		}
		run.Total++
		switch {
		case sm.Expected && pred:
			run.Confusion.TP++
		case !sm.Expected && pred:
			run.Confusion.FP++
		case sm.Expected && !pred:
			run.Confusion.FN++
		default:
			run.Confusion.TN++
		}
		if pred {
			posTotal++
			if strings.TrimSpace(ev) != "" {
				posWithEv++
			}
		}
	}
	run.Precision = ratio(run.Confusion.TP, run.Confusion.TP+run.Confusion.FP)
	run.Recall = ratio(run.Confusion.TP, run.Confusion.TP+run.Confusion.FN)
	run.F1 = ratio2(run.Precision, run.Recall)
	run.Accuracy = ratio(run.Confusion.TP+run.Confusion.TN, run.Total)
	run.FPRate = ratio(run.Confusion.FP, run.Confusion.TP+run.Confusion.FP)
	run.HallucinationRate = ratio(posTotal-posWithEv, posTotal)
	run.Kappa, run.KappaCover = kappa(samples)
	run.Gate = s.gate(run)
	run.Basis = "正类=敏感（expected=true）；precision=TP/(TP+FP)；recall=TP/(TP+FN)；" +
		"F1=调和平均；fp_rate=FP/(TP+FP)（误报占判为敏感比例，FR-CHN-002 ≤10% 对偶面）；" +
		"hallucination_rate=无证据支持的阳性结论/全部阳性结论（AI 面口径，确定性引擎命中自带依据）；" +
		"κ=期望标注与二次标注的一致性（Cohen，仅覆盖有二次标注的样本）；判定失败样本单列 skipped 不计入指标"
	if err := s.store.PutRun(ctx, run); err != nil {
		return Run{}, err
	}
	return run, nil
}

// Runs 运行历史（最新在前）。
func (s *Service) Runs(ctx context.Context, tenant string, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 20
	}
	return s.store.ListRuns(ctx, tenant, limit)
}

// Check 放量门禁检查：返回最近一次运行及其判定；无记录 fail closed（不放量）。
func (s *Service) Check(ctx context.Context, tenant string) (Run, GateDecision, error) {
	rs, err := s.store.ListRuns(ctx, tenant, 1)
	if err != nil {
		return Run{}, GateDecision{}, err
	}
	if len(rs) == 0 {
		return Run{}, GateDecision{
			Allow: false,
			Reasons: []string{"无评测记录——放量门禁 fail closed（先导入/回流样本并执行评测）"},
			Thresholds: s.th, ThresholdSrc: s.thSrc,
			Basis: "无评测不放量：门禁对「没有证据的放行」同样视为不可验证主张（AX-3）",
		}, nil
	}
	// 门禁按**当前**阈值口径重算（run.Gate=运行时快照，仅存档）：G8-01 定稿换配置即生效，
	// 不吃「旧阈值下算出的历史放行」（历史快照不是放行依据，指标未变而口径变紧须立即收紧）。
	run := rs[0]
	return run, s.gate(run), nil
}

// gate 门禁判定（纯计算：逐条点名不达标项；全过才 allow）。
func (s *Service) gate(r Run) GateDecision {
	d := GateDecision{Allow: true, Thresholds: s.th, ThresholdSrc: s.thSrc,
		Basis: "指标不达标不放量（AIL-7/WP-M3-06 DoD）；阈值口径见 threshold_source"}
	add := func(format string, a ...any) {
		d.Allow = false
		d.Reasons = append(d.Reasons, fmt.Sprintf(format, a...))
	}
	if r.Total < s.th.MinSamples {
		add("样本 %d < 最小 %d（统计意义不足）", r.Total, s.th.MinSamples)
	}
	if r.F1 < s.th.F1Min {
		add("F1 %.4f < 阈值 %.2f", r.F1, s.th.F1Min)
	}
	if r.FPRate > s.th.FPRateMax {
		add("误报率 %.4f > 阈值 %.2f", r.FPRate, s.th.FPRateMax)
	}
	if s.th.KappaMin > 0 {
		if r.Kappa == nil {
			add("无二次标注，κ 不可算（标注一致性未验证）")
		} else if *r.Kappa < s.th.KappaMin {
			add("κ %.4f < 阈值 %.2f", *r.Kappa, s.th.KappaMin)
		}
	}
	if r.HallucinationRate > s.th.HallucinationMax {
		add("幻觉率 %.4f > 阈值 %.2f（存在无证据支持的阳性结论）", r.HallucinationRate, s.th.HallucinationMax)
	}
	return d
}

// kappa Cohen's κ：期望标注 vs 第一次二次标注（仅覆盖有二次标注的样本）。
// 无覆盖/单一类别/期望概率为 1 → nil（一致性不可算，不冒充数值）。
func kappa(samples []Sample) (*float64, int) {
	var cover int
	var agree int
	var e1, e2 int // 双方判正类计数
	for _, sm := range samples {
		if len(sm.Relabels) == 0 {
			continue
		}
		rl := sm.Relabels[0]
		cover++
		if sm.Expected == rl.Expected {
			agree++
		}
		if sm.Expected {
			e1++
		}
		if rl.Expected {
			e2++
		}
	}
	if cover == 0 {
		return nil, 0
	}
	po := float64(agree) / float64(cover)
	pe := (float64(e1)/float64(cover))*(float64(e2)/float64(cover)) +
		(float64(cover-e1)/float64(cover))*(float64(cover-e2)/float64(cover))
	if pe >= 1 {
		return nil, cover
	}
	v := round4((po - pe) / (1 - pe))
	return &v, cover
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return round4(float64(num) / float64(den))
}

func ratio2(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return round4(2 * p * r / (p + r))
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }

func sampleID(tenant string, in SampleInput) string {
	return "EV-" + sha12(strings.Join([]string{tenant, in.Kind, in.LedgerID, in.Text,
		strconv.FormatBool(in.Expected)}, "|"))
}

func runID(tenant, subject string) string {
	return "ER-" + sha12(strings.Join([]string{tenant, subject,
		time.Now().UTC().Format(time.RFC3339Nano)}, "|"))
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
