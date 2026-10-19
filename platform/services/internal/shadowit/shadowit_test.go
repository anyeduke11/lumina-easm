package shadowit

import (
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
)

func owner() *ownership.Service { return ownership.NewService() }

// 归属样本：域名属主域（判定最强信号）+ 备案主体匹配。
func ownedInput() Input {
	return Input{
		Tenant: "t-a", Domain: "a.example.cn",
		Identity: ownership.Identity{Tenant: "t-a", Org: "示例科技有限公司", Short: "示例",
			Domains: []string{"example.cn"}, CIDRs: []string{"198.51.100.0/24"}},
		Signals:     ownership.Signals{ICPSubject: "示例科技有限公司", WhoisOrg: "Example Technology Co., Ltd"},
		EvidenceRef: "evi:test",
	}
}

// 疑似样本：非主域、非网段，仅关键词共现（弱信号）。
func suspectInput() Input {
	in := ownedInput()
	in.Domain = "portal.other-cn.net"
	in.Signals = ownership.Signals{KeywordCooccur: 2}
	return in
}

// 无关样本：无任何归属信号。
func unrelatedInput() Input {
	in := ownedInput()
	in.Domain = "someone-else.cn"
	in.Signals = ownership.Signals{}
	return in
}

func hasAction(a Advice, code string) bool {
	for _, act := range a.Actions {
		if act.Code == code {
			return true
		}
	}
	return false
}

// 为什么（FR-MIN-003）：已归属的影子资产也要经人审纳管——
// 「识别出来」≠「自动入账」，建议面不得自带入账副作用。
func TestAdviseOwnedSuggestsAdmitWithReview(t *testing.T) {
	a, err := New(owner()).Advise(ownedInput())
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictOwned {
		t.Fatalf("样本应判归属，实际 %s（%v）", a.Verdict, a.Reasons)
	}
	if !hasAction(a, "admit") {
		t.Errorf("归属资产应给出纳管建议: %+v", a.Actions)
	}
	if !a.NeedsReview {
		t.Error("纳管必须人审（影子资产不自动入账）")
	}
	if len(a.Reasons) == 0 || a.ID == "" || a.EvidenceRef == "" {
		t.Errorf("建议须可解释（依据/ID/证据引用）: %+v", a)
	}
}

// 为什么（FR-MIN-003 验收「影子资产不自动入账」）：疑似资产**不得**给出纳管建议——
// 判定未定的资产若被建议纳管，等于绕开人工复核把疑似资产并入台账（红线）。
func TestAdviseSuspectNeverSuggestsAdmit(t *testing.T) {
	a, err := New(owner()).Advise(suspectInput())
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictSuspect {
		t.Fatalf("样本应判疑似，实际 %s（%v）", a.Verdict, a.Reasons)
	}
	if hasAction(a, "admit") {
		t.Errorf("疑似资产不得给出纳管建议（红线）: %+v", a.Actions)
	}
	if !hasAction(a, "verify") {
		t.Errorf("疑似资产应给出补证建议: %+v", a.Actions)
	}
	if !a.NeedsReview {
		t.Error("疑似资产必须人审")
	}
}

// 为什么：无关资产既不该纳管也不该处置（不是本单位资产）——只给出忽略建议。
func TestAdviseUnrelatedSuggestsIgnore(t *testing.T) {
	a, err := New(owner()).Advise(unrelatedInput())
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != ownership.VerdictUnrelated {
		t.Fatalf("样本应判无关，实际 %s（%v）", a.Verdict, a.Reasons)
	}
	if hasAction(a, "admit") || hasAction(a, "take_down") {
		t.Errorf("无关资产不得纳管/处置: %+v", a.Actions)
	}
	if !hasAction(a, "ignore") {
		t.Errorf("无关资产应给出忽略建议: %+v", a.Actions)
	}
}

// 为什么：建议须机器可消费且可审计——每条动作为确定性排序、带依据与优先级。
func TestAdviseActionsAreOrderedAndExplained(t *testing.T) {
	a, err := New(owner()).Advise(suspectInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Actions) == 0 {
		t.Fatal("应给出动作建议")
	}
	for i, act := range a.Actions {
		if act.Code == "" || act.Name == "" || act.Basis == "" {
			t.Errorf("动作[%d] 缺依据/名称: %+v", i, act)
		}
		if i > 0 && a.Actions[i-1].Priority > act.Priority {
			t.Errorf("动作应按优先级升序: %+v", a.Actions)
		}
	}
}

// 为什么（AX-3 可复现）：同输入两次建议必须完全一致（含 ID、动作顺序、依据）。
func TestAdviseDeterministic(t *testing.T) {
	s := New(owner())
	a1, err := s.Advise(ownedInput())
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.Advise(ownedInput())
	if err != nil {
		t.Fatal(err)
	}
	if a1.ID != a2.ID || a1.Verdict != a2.Verdict || a1.Confidence != a2.Confidence {
		t.Errorf("建议不确定: %+v vs %+v", a1, a2)
	}
	if len(a1.Actions) != len(a2.Actions) {
		t.Fatalf("动作数量不一致: %d vs %d", len(a1.Actions), len(a2.Actions))
	}
	for i := range a1.Actions {
		if a1.Actions[i] != a2.Actions[i] {
			t.Errorf("动作[%d] 不一致: %+v vs %+v", i, a1.Actions[i], a2.Actions[i])
		}
	}
}

// 为什么（红线守卫须落 API 层而非仅文档）：纳管必须显式人审同意且判定为归属。
func TestAdmitRequiresReviewerAndOwnedVerdict(t *testing.T) {
	s := New(owner())
	adv, err := s.Advise(ownedInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAdmit(adv, "", "张三"); err == nil {
		t.Error("缺人审人应拒绝纳管")
	}
	if err := s.CheckAdmit(adv, "admit", "张三"); err != nil {
		t.Errorf("归属+人审应放行: %v", err)
	}
	sus, err := s.Advise(suspectInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAdmit(sus, "admit", "张三"); err == nil {
		t.Error("疑似资产纳管必须被拒（红线）")
	}
}
