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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
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
}

type Service struct {
	owner *ownership.Service
}

// New 构造建议服务（归属判定必须与主链路同一服务实例，口径唯一）。
func New(owner *ownership.Service) *Service {
	return &Service{owner: owner}
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
