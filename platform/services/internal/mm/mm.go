// Package mm 多模态富化（M3-D / WP-M3-03 / FR-CLS-006 OCR 判敏）。
//
// 编号：AIL-5/6（富化结果进图谱且可解释）、ENH-03（AI 推理面，经 ai.Provider 接缝装配）、
// AX-2（AI 结论=ai_assisted 参考，**不入台账**——台账仍走确定性三重门）、AX-5（人在环：
// 单点分析由请求方显式发起并复核）、NFR-SEC（图片经 data URL/公网 URL 透传，不落盘）。
//
// 诚实边界：模型输出不可解析 → unverifiable（不冒充判定、不入图）；
// 资产不在图内 → graphed=false（不伪造富化落点）；ENH-03 未装配 → 端点 501。
package mm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
)

// 判定 kind（枚举固定）。
const (
	KindSensitive    = "sensitive"
	KindBenign       = "benign"
	KindUnverifiable = "unverifiable"
)

// 图谱富化 props 键（mm_ 前缀，AIL-5/6 可解释）。
const (
	propMmSensitivity = "mm_sensitivity"
	propMmKind        = "mm_kind"
	propMmBasis       = "mm_basis"
	propMmModel       = "mm_model"
	propMmTS          = "mm_ts"
	propMmFindings    = "mm_findings"
)

// Input 一次多模态判敏输入（ImageURL=data URL 或公网 http(s) 图片）。
type Input struct {
	Tenant      string `json:"-"`
	AssetFP     string `json:"asset_fp,omitempty"` // 可选：在图内则富化挂载到该实体
	ImageURL    string `json:"image_url"`
	Question    string `json:"question,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// Finding 一条发现（kind/内容/依据——可解释面）。
type Finding struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
	Basis string `json:"basis"`
}

// Result 判敏结论（AI 结论=ai_assisted 参考；图谱富化状态如实回显）。
type Result struct {
	ID         string    `json:"id"`
	Tenant     string    `json:"tenant"`
	AssetFP    string    `json:"asset_fp,omitempty"`
	Kind       string    `json:"kind"`
	Sensitive  bool      `json:"sensitive"`
	Findings   []Finding `json:"findings"`
	Basis      string    `json:"basis"`
	Model      string    `json:"model"`
	Graphed    bool      `json:"graphed"`
	AIAssisted bool      `json:"ai_assisted"`
	TS         time.Time `json:"ts"`
}

// Graph 图谱端口（富化落点；*graph.Service 满足）。
type Graph interface {
	UpsertEntity(ctx context.Context, e graph.Entity) (graph.Entity, bool, error)
	Entities(ctx context.Context, tenant string) ([]graph.Entity, error)
}

// Service 多模态判敏服务（provider/graph 未装配=端点 501）。
type Service struct {
	p      ai.Provider
	gw     Graph
	usageS *usage.Service // M4-07 计量（可选；nil=不计量，如实标注）
}

// New 构造（任一依赖缺失 → Ready()=false → 端点 501，不半可用）。
func New(p ai.Provider, gw Graph) *Service { return &Service{p: p, gw: gw} }

// SetUsage 装配计量（M4-07/FR-HRN-10：AI 调用按租户留痕；nil=不计量）。
func (s *Service) SetUsage(u *usage.Service) *Service { s.usageS = u; return s }

// Ready 依赖齐备（provider + graph）。
func (s *Service) Ready() bool { return s.p != nil && s.gw != nil }

var (
	ErrNoProvider = errors.New("mm: AI provider 未装配（ENH-03 能力边界）")
	ErrNoGraph    = errors.New("mm: 图谱未装配")
	// ErrInvalid 输入不合法（httpapi 映射 400）。
	ErrInvalid = errors.New("mm: 非法请求")
)

// systemPrompt 判敏指令（只输出 JSON；要求依据可解释；不引导模型越权给处置动作）。
const systemPrompt = `你是互联网敏感信息泄露排查的多模态判敏助手。分析用户给出的截图/图片，` +
	`判断其中是否包含敏感信息（如：明文口令/云凭据/API Key、数据库连接串、身份证/手机号等个人信息、` +
	`内网拓扑与端口、源代码/数据库结构、后台入口等）。只输出一个 JSON 对象，不要输出任何其他文字：` +
	`{"sensitive":true|false,"kind":"sensitive|benign","findings":[{"kind":"发现类别","value":"脱敏后的片段","basis":"判定依据"}],"basis":"整体判定依据"}` +
	`。要求：value 必须脱敏（不得完整回显凭据/个人信息）；findings 可为空数组；依据必须具体可复核。`

// Analyze 执行一次多模态判敏：AI 推理 → JSON 解析（失败=unverifiable）→ 图谱富化（可解释 props）。
func (s *Service) Analyze(ctx context.Context, in Input) (Result, error) {
	if s.p == nil {
		return Result{}, ErrNoProvider
	}
	if s.gw == nil {
		return Result{}, ErrNoGraph
	}
	if strings.TrimSpace(in.Tenant) == "" {
		return Result{}, fmt.Errorf("%w: 租户必填", ErrInvalid)
	}
	if strings.TrimSpace(in.ImageURL) == "" {
		return Result{}, fmt.Errorf("%w: image_url 必填（data URL 或 http(s) 图片）", ErrInvalid)
	}
	q := strings.TrimSpace(in.Question)
	if q == "" {
		q = "判断该图片是否包含敏感信息，按系统指令输出 JSON。"
	}
	resp, err := s.p.Chat(ctx, ai.ChatRequest{Messages: []ai.Message{
		{Role: "system", Text: systemPrompt},
		{Role: "user", Text: q, ImageURL: in.ImageURL},
	}})
	if err != nil {
		return Result{}, fmt.Errorf("mm: AI 推理失败: %w", err)
	}
	r := Result{
		ID:         resultID(in.Tenant, in.AssetFP, in.ImageURL),
		Tenant:     in.Tenant,
		AssetFP:    in.AssetFP,
		Model:      resp.Model,
		AIAssisted: true,
		TS:         time.Now().UTC(),
		Findings:   []Finding{},
	}
	// M4-07：AI 调用即计量（解析成败不影响——上游消耗已发生；计量失败不阻断判敏，上浮留痕）
	if s.usageS != nil {
		if _, uerr := s.usageS.Record(ctx, usage.Event{Tenant: in.Tenant, Feature: usage.FeatureMM,
			Model: resp.Model, PromptTokens: resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens, TotalTokens: resp.Usage.TotalTokens}); uerr != nil {
			return Result{}, fmt.Errorf("mm: 计量留痕失败: %w", uerr)
		}
	}
	var parsed struct {
		Sensitive bool      `json:"sensitive"`
		Kind      string    `json:"kind"`
		Findings  []Finding `json:"findings"`
		Basis     string    `json:"basis"`
	}
	if err := json.Unmarshal([]byte(stripFences(resp.Content)), &parsed); err != nil {
		r.Kind = KindUnverifiable
		r.Basis = "模型输出不可解析为约定 JSON（如实标注，不冒充判定、不入图）：" + truncate(resp.Content, 200)
		return r, nil
	}
	if parsed.Sensitive {
		r.Sensitive = true
		r.Kind = KindSensitive
	} else {
		r.Kind = KindBenign
	}
	if parsed.Kind == KindSensitive || parsed.Kind == KindBenign {
		r.Kind = parsed.Kind
	}
	for _, f := range parsed.Findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Basis = strings.TrimSpace(f.Basis)
		if f.Kind != "" || f.Basis != "" {
			r.Findings = append(r.Findings, f)
		}
	}
	r.Basis = strings.TrimSpace(parsed.Basis)
	if err := s.enrich(ctx, in, r, parsed.Findings); err != nil {
		return Result{}, err
	}
	return r, nil
}

// enrich 富化入图：mm_* props 挂到既有实体（MergeEntity 非破坏合并，指纹不变）。
// 资产不在图内/unverifiable → 不落 props（不伪造富化落点与结论）。
func (s *Service) enrich(ctx context.Context, in Input, r Result, findings []Finding) error {
	if strings.TrimSpace(in.AssetFP) == "" || r.Kind == KindUnverifiable {
		return nil
	}
	ents, err := s.gw.Entities(ctx, in.Tenant)
	if err != nil {
		return fmt.Errorf("mm: 图谱实体读取失败: %w", err)
	}
	var cur *graph.Entity
	for i := range ents {
		if ents[i].Fingerprint == in.AssetFP {
			cur = &ents[i]
			break
		}
	}
	if cur == nil {
		return nil // 不在图内：graphed=false（宁可不连图，不伪造）
	}
	fj, _ := json.Marshal(findings)
	props := map[string]string{
		propMmSensitivity: r.Kind,
		propMmKind:        r.Kind,
		propMmBasis:       truncate(r.Basis, 500),
		propMmModel:       r.Model,
		propMmTS:          r.TS.Format(time.RFC3339),
		propMmFindings:    string(fj),
	}
	merged := graph.Entity{
		Kind: cur.Kind, Tenant: cur.Tenant, Fingerprint: cur.Fingerprint,
		Props: props, InScope: true, Sources: []string{"mm:analyze"},
	}
	if _, _, err := s.gw.UpsertEntity(ctx, merged); err != nil {
		return fmt.Errorf("mm: 富化入图失败: %w", err)
	}
	r.Graphed = true
	return nil
}

// stripFences 剥离 ```json 围栏与前后杂文（取首尾大括号之间）。
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			return s[i : j+1]
		}
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

func resultID(tenant, fp, image string) string {
	sum := sha256.Sum256([]byte(tenant + "|" + fp + "|" + image + "|" + time.Now().UTC().Format(time.RFC3339Nano)))
	return "MM-" + hex.EncodeToString(sum[:])[:12]
}
