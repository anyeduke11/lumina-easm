// 影子 IT 收敛建议与纳管人审面（M3-C / FR-MIN-003 / WP-M3-04）。
//
// 编号：FR-MIN-003（识别无 CMDB 记录的待归属资产；**验收：影子资产不自动入账，
// 进人工复核**）、WP-M3-04（待归属资产识别 + 收敛建议）、AX-2 确定性、AX-3 可解释。
//
// 红线落法（不靠文档靠代码）：
//   - Advise 只产出建议，**不写资产、不写图谱**（无副作用，纯计算）；
//   - 疑似/无关资产的候选动作里**不出现 admit**（纳管）——纳管建议只在判定时给出；
//   - 真正纳管必须走人审动作（reviewer 必填）+ 判定为归属，由 CheckAdmit 闸把关。
//
// 判定复用 ownership.Judge（12 类依据加权）——不另起一套归属口径（C-6 口径唯一）。
package shadowit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
)

// 动作码（候选收敛动作；人审后执行，平台不自动执行）。
const (
	ActionAdmit    = "admit"
	ActionObserve  = "observe"
	ActionVerify   = "verify"
	ActionTakeDown = "take_down"
	ActionIgnore   = "ignore"
)

var (
	// ErrBadInput 输入不完整（租户/域名必填）。
	ErrBadInput = errors.New("shadow: 租户与域名为必填")
	// ErrReviewRequired 纳管缺人审人或未选择纳管动作（AX-5 人在环）。
	ErrReviewRequired = errors.New("shadow: 纳管须经人审（reviewer 必填且动作=admit）")
	// ErrNotOwned 疑似/无关资产不得纳管（FR-MIN-003 验收红线）。
	ErrNotOwned = errors.New("shadow: 仅判定为归属的资产可纳管（疑似/无关须先人工复核）")
)

// Input 建议输入（归属判定所需全部信号；缺失即零值=弱信号）。
type Input struct {
	Tenant      string
	Domain      string
	Identity    ownership.Identity
	Signals     ownership.Signals
	EvidenceRef string
}

// Action 一条收敛动作（可处置：代码/名称/依据/优先级）。
type Action struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Basis    string `json:"basis"`
	Priority int    `json:"priority"`
}

// Advice 一条待归属资产建议（可解释：依据 + 候选动作 + 人审要求）。
type Advice struct {
	ID          string   `json:"id"`
	Tenant      string   `json:"tenant"`
	Domain      string   `json:"domain"`
	Verdict     string   `json:"verdict"`
	Confidence  float64  `json:"confidence"`
	Reasons     []string `json:"reasons"`
	Actions     []Action `json:"actions"`
	NeedsReview bool     `json:"needs_review"`
	EvidenceRef string   `json:"evidence_ref"`
	// AIBasis AI 生成的处置说明文案（ENH-03/M3-C-AI）：**仅文案层**，判定与动作集不变；
	// 仅 WithAI 装配且显式走 AdviseWithAI 时出现（默认确定性路径无此字段，AX-2）。
	AIBasis string `json:"ai_basis,omitempty"`
	AIModel string `json:"ai_model,omitempty"`
}

// ErrNoAI with_ai 请求但 provider 未装配（501 诚实边界，不静默降级）。
var ErrNoAI = errors.New("shadow: AI 文案 provider 未装配（ENH-03 能力边界）")

type Service struct {
	owner  *ownership.Service
	ai     ai.Provider
	usageS *usage.Service // M4-07 计量（可选；nil=不计量）
}

// New 构造建议服务（归属判定必须与主链路同一服务实例，口径唯一）。
func New(owner *ownership.Service) *Service {
	return &Service{owner: owner}
}

// WithAI 装配 AI 文案 provider（ENH-03 接缝；nil/未调用=仅确定性路径）。
func (s *Service) WithAI(p ai.Provider) *Service {
	s.ai = p
	return s
}

// WithUsage 装配计量（M4-07/FR-HRN-10：with_ai 调用按租户留痕；nil=不计量）。
func (s *Service) WithUsage(u *usage.Service) *Service {
	s.usageS = u
	return s
}

// Advise 生成收敛建议（纯计算、无副作用：不写资产、不写图谱、不入队）。
func (s *Service) Advise(in Input) (Advice, error) {
	if strings.TrimSpace(in.Tenant) == "" || strings.TrimSpace(in.Domain) == "" {
		return Advice{}, ErrBadInput
	}
	v := s.owner.Judge(in.Identity, in.Domain, in.Signals)
	a := Advice{
		ID:          adviceID(in.Tenant, in.Domain),
		Tenant:      in.Tenant,
		Domain:      strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), ".")),
		Verdict:     v.Verdict,
		Confidence:  v.Confidence,
		Reasons:     append([]string{}, v.Reasons...),
		NeedsReview: true, // 红线：任何纳管/处置都必须人审（FR-MIN-003）
		EvidenceRef: in.EvidenceRef,
	}
	a.Actions = actionsFor(v.Verdict, v.Confidence)
	return a, nil
}

// AdviseWithAI 生成建议 + AI 处置说明文案（ENH-03/M3-C-AI）。
// 红线：AI 只产出给安全运营阅读的文案（AIBasis），**不触碰判定、理由与动作集**；
// provider 未装配=ErrNoAI；上游失败=错误上浮（fail loud，不拿确定性文案冒充 AI 文案）。
func (s *Service) AdviseWithAI(ctx context.Context, in Input) (Advice, error) {
	a, err := s.Advise(in)
	if err != nil {
		return Advice{}, err
	}
	if s.ai == nil {
		return Advice{}, ErrNoAI
	}
	var actDesc strings.Builder
	for _, act := range a.Actions {
		actDesc.WriteString(fmt.Sprintf("- %s（%s）：%s\n", act.Code, act.Name, act.Basis))
	}
	prompt := fmt.Sprintf(
		"以下是资产归属判定结果，请为安全运营人员写一段不超过 120 字的处置说明（中文，具体、可执行）。"+
			"严格遵守：只做文案润色与解释，不得新增或更改处置动作，不得建议自动化执行。"+
			"判定=%s；置信度=%.2f；理由=%s；候选动作=\n%s",
		a.Verdict, a.Confidence, strings.Join(a.Reasons, "；"), actDesc.String())
	resp, err := s.ai.Chat(ctx, ai.ChatRequest{Messages: []ai.Message{
		{Role: "system", Text: "你是企业安全运营平台的建议文案助手，只输出处置说明正文。"},
		{Role: "user", Text: prompt},
	}}) // 不设 max_tokens：推理型模型的思考会消耗配额，设小了 content 为空（ai 包已对空回执 fail loud）
	if err != nil {
		return Advice{}, fmt.Errorf("shadow: AI 文案失败: %w", err)
	}
	a.AIBasis = strings.TrimSpace(resp.Content)
	a.AIModel = resp.Model
	// M4-07：AI 调用即计量（文案已生成=消耗已发生；计量失败上浮不静默）
	if s.usageS != nil {
		if _, uerr := s.usageS.Record(ctx, usage.Event{Tenant: a.Tenant, Feature: usage.FeatureShadowAI,
			Model: resp.Model, PromptTokens: resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens, TotalTokens: resp.Usage.TotalTokens}); uerr != nil {
			return Advice{}, fmt.Errorf("shadow: 计量留痕失败: %w", uerr)
		}
	}
	return a, nil
}

// CheckAdmit 纳管闸（人审面）：判定非归属/缺人审人/非纳管动作 一律拒绝。
func (s *Service) CheckAdmit(a Advice, action, reviewer string) error {
	if strings.TrimSpace(reviewer) == "" || action != ActionAdmit {
		return ErrReviewRequired
	}
	if a.Verdict != ownership.VerdictOwned {
		return ErrNotOwned
	}
	return nil
}

// actionsFor 按判定给出候选动作（确定性、按优先级升序）。
// 关键红线：疑似/无关的动作集合内**不含** admit——纳管建议只在归属时出现。
func actionsFor(verdict string, conf float64) []Action {
	basis := fmt.Sprintf("判定%s（置信度 %.2f）", verdict, conf)
	switch verdict {
	case ownership.VerdictOwned:
		return []Action{
			{Code: ActionAdmit, Name: "纳管入账：纳入资产台账与常规监测", Basis: basis, Priority: 1},
			{Code: ActionObserve, Name: "纳入常规监测（暴露面/变更告警）", Basis: basis, Priority: 3},
		}
	case ownership.VerdictSuspect:
		return []Action{
			{Code: ActionVerify, Name: "补采归属证据：证书/备案/WHOIS/指纹", Basis: basis + "，证据不足暂不纳管", Priority: 1},
			{Code: ActionTakeDown, Name: "确认为废弃资产则下线/关停（需责任人确认）", Basis: basis + "，废弃资产优先收敛", Priority: 2},
			{Code: ActionObserve, Name: "纳入观察名单，暂不入账", Basis: basis + "，待证据补全后复核", Priority: 3},
		}
	default: // 无关
		return []Action{
			{Code: ActionIgnore, Name: "登记为无关：不入账、不处置", Basis: basis + "，非本单位资产", Priority: 1},
		}
	}
}

// adviceID 建议 ID（确定性：sha12(租户|域名)）。
func adviceID(tenant, domain string) string {
	sum := sha256.Sum256([]byte(tenant + "|" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))))
	return "SA-" + hex.EncodeToString(sum[:])[:12]
}
