package shadowit

import (
	"context"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

// ---- 夹具 ----

func ident() ownership.Identity {
	return ownership.Identity{Tenant: "t-a", Org: "华东联合数据服务集团有限公司", Short: "华东数服",
		Domains: []string{"hddata.cn"}, CIDRs: []string{"203.0.113.0/24"}}
}

func adviseInput(domain string, sig ownership.Signals) Input {
	return Input{Tenant: "t-a", Domain: domain, Identity: ident(), Signals: sig, EvidenceRef: "evi://1"}
}

// mockAI 固定回执：只验证接缝与红线（文案层注入、动作集不变），不依赖真实上游。
type mockAI struct{ content string; err error }

func (m mockAI) Name() string { return "mock" }
func (m mockAI) Chat(_ context.Context, _ ai.ChatRequest) (ai.ChatResponse, error) {
	if m.err != nil {
		return ai.ChatResponse{}, m.err
	}
	return ai.ChatResponse{Content: m.content, Model: "mock-1"}, nil
}

// ---- 确定性建议（M3-C 回归面）----

// FR-MIN-003 验收红线：疑似/无关资产的候选动作里不得出现 admit——纳管建议只在归属时出现。
func TestAdviseSuspectNeverSuggestsAdmit(t *testing.T) {
	svc := New(ownership.NewService())
	a, err := svc.Advise(adviseInput("stray.example.cn", ownership.Signals{KeywordCooccur: 3}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictSuspect {
		t.Fatalf("夹具期望疑似，实际 %+v", a)
	}
	for _, act := range a.Actions {
		if act.Code == ActionAdmit {
			t.Fatalf("疑似资产建议不得含 admit（红线）: %+v", a.Actions)
		}
	}
	if !a.NeedsReview {
		t.Fatal("疑似必须走人工复核")
	}
}

func TestAdviseOwnedSuggestsAdmit(t *testing.T) {
	svc := New(ownership.NewService())
	a, err := svc.Advise(adviseInput("portal.hddata.cn", ownership.Signals{}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictOwned {
		t.Fatalf("主域子域应判归属: %+v", a)
	}
	has := false
	for _, act := range a.Actions {
		if act.Code == ActionAdmit {
			has = true
		}
	}
	if !has {
		t.Fatalf("归属应给出纳管候选: %+v", a.Actions)
	}
	if !a.NeedsReview {
		t.Fatal("纳管仍须人审（AX-5）")
	}
}

func TestAdviseUnrelatedOnlyIgnore(t *testing.T) {
	svc := New(ownership.NewService())
	a, err := svc.Advise(adviseInput("someone-else.com", ownership.Signals{}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictUnrelated || len(a.Actions) != 1 || a.Actions[0].Code != ActionIgnore {
		t.Fatalf("无关资产只应有 ignore 动作: %+v", a)
	}
}

func TestAdviseValidationAndID(t *testing.T) {
	svc := New(ownership.NewService())
	if _, err := svc.Advise(Input{Tenant: "t-a"}); err != ErrBadInput {
		t.Fatalf("缺域名应 ErrBadInput: %v", err)
	}
	a1, _ := svc.Advise(adviseInput("Portal.HDDATA.cn.", ownership.Signals{}))
	a2, _ := svc.Advise(adviseInput("portal.hddata.cn", ownership.Signals{}))
	if a1.ID != a2.ID || !strings.HasPrefix(a1.ID, "SA-") {
		t.Fatalf("建议 ID 应确定性且大小写/尾点归一: %s vs %s", a1.ID, a2.ID)
	}
	if a1.Domain != "portal.hddata.cn" {
		t.Fatalf("域名应归一: %s", a1.Domain)
	}
}

// 纳管双闸（M3-C 红线）：缺人审人=ErrReviewRequired；疑似/无关=ErrNotOwned；归属+人审=放行。
func TestCheckAdmitGates(t *testing.T) {
	svc := New(ownership.NewService())
	owned, _ := svc.Advise(adviseInput("portal.hddata.cn", ownership.Signals{}))
	suspect, _ := svc.Advise(adviseInput("stray.example.cn", ownership.Signals{KeywordCooccur: 3}))
	if err := svc.CheckAdmit(owned, ActionAdmit, ""); err != ErrReviewRequired {
		t.Fatalf("缺人审人应 ErrReviewRequired: %v", err)
	}
	if err := svc.CheckAdmit(owned, ActionObserve, "u1"); err != ErrReviewRequired {
		t.Fatalf("非纳管动作应 ErrReviewRequired: %v", err)
	}
	if err := svc.CheckAdmit(suspect, ActionAdmit, "u1"); err != ErrNotOwned {
		t.Fatalf("疑似纳管应 ErrNotOwned: %v", err)
	}
	if err := svc.CheckAdmit(owned, ActionAdmit, "u1"); err != nil {
		t.Fatalf("归属+人审应放行: %v", err)
	}
}

// ---- AI 文案接缝（M3-C-AI / ENH-03）----

// 红线回归：AI 文案只写 AIBasis 层——动作集与确定性判定完全不变，
// 疑似资产的候选动作仍不得出现 admit（AI 不得越权给出纳管建议）。
func TestAdviseWithAINeverChangesActions(t *testing.T) {
	svc := New(ownership.NewService()).WithAI(mockAI{content: "建议先补采证书与备案证据，再评估下线。"})
	in := adviseInput("stray.example.cn", ownership.Signals{KeywordCooccur: 3})
	base, err := svc.Advise(in)
	if err != nil {
		t.Fatal(err)
	}
	aiAdv, err := svc.AdviseWithAI(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if aiAdv.AIBasis == "" || aiAdv.AIModel != "mock-1" {
		t.Fatalf("AI 文案应注入 AIBasis/AIModel: %+v", aiAdv)
	}
	if strings.Join(aiAdv.Reasons, "|") != strings.Join(base.Reasons, "|") ||
		aiAdv.Verdict != base.Verdict || aiAdv.NeedsReview != base.NeedsReview {
		t.Fatalf("AI 文案不得改变确定性判定: %+v vs %+v", aiAdv, base)
	}
	for _, a := range aiAdv.Actions {
		if a.Code == ActionAdmit {
			t.Fatalf("疑似资产的 AI 建议仍不得含 admit（红线）: %+v", aiAdv.Actions)
		}
	}
	if len(aiAdv.Actions) != len(base.Actions) {
		t.Fatalf("AI 文案不得增删动作: %+v vs %+v", aiAdv.Actions, base.Actions)
	}
}

func TestAdviseWithAINoProvider(t *testing.T) {
	svc := New(ownership.NewService())
	if _, err := svc.AdviseWithAI(context.Background(), adviseInput("portal.hddata.cn", ownership.Signals{})); err != ErrNoAI {
		t.Fatalf("未装配 provider 应 ErrNoAI（501 诚实边界），实际 %v", err)
	}
}

func TestAdviseWithAIUpstreamFailLoud(t *testing.T) {
	svc := New(ownership.NewService()).WithAI(mockAI{err: context.DeadlineExceeded})
	if _, err := svc.AdviseWithAI(context.Background(), adviseInput("portal.hddata.cn", ownership.Signals{})); err == nil {
		t.Fatal("AI 调用失败应上浮（fail loud，不静默降级为确定性文案冒充 AI 文案）")
	}
}

// 默认路径不受影响：Advise 纯确定性，无 AI 字段（AX-2）。
func TestAdviseDeterministicUnchanged(t *testing.T) {
	svc := New(ownership.NewService()).WithAI(mockAI{content: "x"})
	a, err := svc.Advise(adviseInput("portal.hddata.cn", ownership.Signals{}))
	if err != nil {
		t.Fatal(err)
	}
	if a.AIBasis != "" || a.AIModel != "" {
		t.Fatalf("默认 Advise 不得引入 AI 字段: %+v", a)
	}
}
