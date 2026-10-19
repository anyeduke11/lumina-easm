package ledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func newSvc() (*Service, *audit.MemLog) {
	l := &audit.MemLog{}
	return NewService(NewMemStore(), l), l
}

func full() Item {
	return Item{
		ID: "L-2026-0001", Tenant: "t-a", Phase: "P2", Category: "代码密码类",
		Asset: "a.hddata.cn", Title: "数据库备份可下载", Level: "严重", Source: "P3/Dirsearch",
		Found: time.Now(), Action: "删除", Owner: "运维部", Due: time.Now().AddDate(0, 0, 1),
		Status: StatusOpen,
	}
}

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

// 为什么（FR-LGR-001 / A-07 / 一票否决③）：必填字段缺失必须拒绝入账——
// 这是监管台账可考核的底线，任何字段可绕过即验收失败。
func TestCreateRequiresAllFields(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	cases := []func(i *Item){
		func(i *Item) { i.Phase = "" },
		func(i *Item) { i.Category = "" },
		func(i *Item) { i.Title = "" },
		func(i *Item) { i.Level = "" },
		func(i *Item) { i.Action = "" },
		func(i *Item) { i.Owner = "" },
		func(i *Item) { i.Due = time.Time{} },
		func(i *Item) { i.Source = "" },
	}
	for i, mut := range cases {
		it := full()
		mut(&it)
		if err := s.Create(ctx, admin(), "req", it); err == nil {
			t.Errorf("case %d 必填缺失应拒绝入账", i)
		}
	}
	if err := s.Create(ctx, admin(), "req", full()); err != nil {
		t.Errorf("完整条目应成功: %v", err)
	}
	// 枚举口径（C-6）：阶段、分类、等级、措施必须合法
	bad := full()
	bad.Phase = "P6"
	if err := s.Create(ctx, admin(), "r", bad); err == nil {
		t.Error("P6 非法阶段应拒绝")
	}
	bad2 := full()
	bad2.Category = "神秘类"
	if err := s.Create(ctx, admin(), "r", bad2); err == nil {
		t.Error("非法分类应拒绝")
	}
	bad3 := full()
	bad3.Action = "视而不见"
	if err := s.Create(ctx, admin(), "r", bad3); err == nil {
		t.Error("非7类措施应拒绝")
	}
}

// 为什么（FR-LGR-005）：闭环必须经复测验证——验证失败回退「整改中」并记录原因；
// 若允许直接置已闭环，整改闭环率指标即造假（AX-4）。
func TestVerifyGatesClosed(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	it := full()
	if err := s.Create(ctx, admin(), "r", it); err != nil {
		t.Fatal(err)
	}
	// 直接置「已闭环」被拒绝
	if err := s.SetStatus(ctx, admin(), "r", it.ID, StatusClosed); err == nil {
		t.Error("未复测不得直接闭环")
	}
	// 整改中
	if err := s.SetStatus(ctx, admin(), "r", it.ID, StatusDoing); err != nil {
		t.Fatal(err)
	}
	// 复测失败（refuted）→ 回退整改中并记录原因（S-2 门3 语义）
	rec, err := s.Verify(ctx, admin(), "v1", it.ID, Verification{
		Method: MethodCrossTool, Result: ResultRefuted, EvidenceRef: "evidence://x", Note: "目标仍可下载备份文件",
	})
	if err != nil || rec.Result != ResultRefuted {
		t.Errorf("复测失败应返回 refuted 记录: %+v err=%v", rec, err)
	}
	got, _ := s.Get(ctx, admin(), "g", it.ID)
	if got.Status != StatusDoing || !strings.Contains(got.Note, "仍可下载") {
		t.Errorf("复测失败须回退整改中并记录原因: %+v", got)
	}
	// 复测通过（reproduced，带证据引用）→ 已闭环
	if _, err := s.Verify(ctx, admin(), "v2", it.ID, Verification{
		Method: MethodManual, Result: ResultReproduced, EvidenceRef: "minio://easm-evidence/verify/x.json",
	}); err != nil {
		t.Fatal("复测通过应闭环")
	}
	got, _ = s.Get(ctx, admin(), "g", it.ID)
	if got.Status != StatusClosed {
		t.Errorf("复测通过应为已闭环，实际 %s", got.Status)
	}
	if len(got.Verifs) != 2 {
		t.Errorf("验证记录应累计 2 条: %+v", got.Verifs)
	}
}

// 为什么（FR-LGR-007 / 一票否决⑤）：通报状态迁移与四态计数一致性。
func TestNotifyStateAndFilter(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		it := full()
		it.ID = "L-2026-000" + string(rune('1'+i))
		if err := s.Create(ctx, admin(), "r", it); err != nil {
			t.Fatal(err)
		}
		switch i {
		case 1:
			_ = s.SetStatus(ctx, admin(), "s", it.ID, StatusDoing)
			_ = s.SetStatus(ctx, admin(), "s", it.ID, StatusOpen) // doing→open 非法，应仍 open? 见下
		case 3:
			if err := s.MarkNotify(ctx, admin(), "n", it.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	list, _ := s.List(ctx, admin(), "l", Filter{Status: StatusNotify})
	if len(list) != 1 || list[0].ID != "L-2026-0004" {
		t.Errorf("待通报筛选应 1 条，实际 %+v", list)
	}
	counts := s.Counts(ctx, admin())
	// 迁移后：0=open, 1=doing（open→doing 合法，doing→open 非法被忽略）, 2=open, 3=notify
	if counts["total"] != 4 || counts[StatusOpen] != 2 || counts[StatusDoing] != 1 || counts[StatusNotify] != 1 {
		t.Errorf("四态计数错误: %v", counts)
	}
	// open→closed 非法、doing→closed 需复测：状态机防造假
	it := full()
	it.ID = "L-2026-0010"
	_ = s.Create(ctx, admin(), "r", it)
	if err := s.SetStatus(ctx, admin(), "s", it.ID, StatusClosed); err == nil {
		t.Error("直接置闭环必须非法")
	}
}

// 为什么：到期预警（FR-LGR-004）——临期/逾期必须是可查询的一等状态。
func TestOverdue(t *testing.T) {
	s, _ := newSvc()
	ctx := context.Background()
	it := full()
	it.Due = time.Now().Add(12 * time.Hour) // 临期（<3天）
	_ = s.Create(ctx, admin(), "r", it)
	it2 := full()
	it2.ID = "L-2026-0999"
	it2.Due = time.Now().AddDate(0, 0, -2) // 已逾期
	it2.Status = StatusOpen
	_ = s.Create(ctx, admin(), "r", it2)
	near := s.NearDue(ctx, admin(), 3*24*time.Hour)
	if len(near) != 1 || near[0].ID != it.ID {
		t.Errorf("临期应仅 1 条，实际 %+v", near)
	}
	over := s.Overdue(ctx, admin())
	if len(over) != 1 || over[0].ID != "L-2026-0999" {
		t.Errorf("逾期应仅 1 条，实际 %+v", over)
	}
}

// 跨租户隔离（一票否决④）：t-b 主体不可读写 t-a 条目，且留 deny 审计。
func TestCrossTenantDeniedAndAudited(t *testing.T) {
	s, l := newSvc()
	ctx := context.Background()
	if err := s.Create(ctx, admin(), "r", full()); err != nil {
		t.Fatal(err)
	}
	tb := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}}
	if _, err := s.Get(ctx, tb, "g", "L-2026-0001"); err != rbac.ErrCrossTenant {
		t.Errorf("跨租户读取应拒绝，实际 %v", err)
	}
	snap := l.Snapshot()
	if snap[len(snap)-1].Result != audit.ResultDeny {
		t.Error("跨租户读取必须落 deny 审计")
	}
}

// ---- V-5 零误报门1（交叉去噪 / AX-3 / 设计方案 §7.1 门1）----

// 为什么：单源证据（一个正则/一个工具）不得标「严重」——LLM 从零找漏洞误报率 >90% 的
// 行业实证说明：确定性单点命中只够「高」；「严重」必须有两个以上独立信源交叉支撑。
// 降级而非拒账：单源命中仍是真实发现（拒账=丢事实），但级别必须诚实。
func TestSevereRequiresCrossCheck(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		xchk   []string
		refute []RefuteCheck
		want   string // 期望入库等级
		note   string // 期望 Note 包含的子串（空=不要求）
	}{
		{"无信源", nil, nil, "高", "门1未过"},
		{"单信源", []string{"rule:R-KEY"}, nil, "高", "门1未过"},
		{"同源重复标注不算交叉", []string{"rule:R-KEY", "rule:R-KEY"}, nil, "高", "门1未过"},
		{"空串信源不算数", []string{"", "  "}, nil, "高", "门1未过"},
		{"门1过门2未过", []string{"rule:R-KEY", "rule:R-SRCPKG"}, nil, "高", "门2未过"},
		{"门1门2全过", []string{"rule:R-KEY", "rule:R-SRCPKG"}, answeredRefute(), "严重", ""},
		{"规则+人工复核", []string{"rule:R-KEY", "人工复核:u1"}, answeredRefute(), "严重", ""},
		{"非严重级不受门约束", []string{"rule:R-PORT"}, nil, "高", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newSvc()
			it := full()
			it.ID = "L-" + c.name
			it.Level = "严重"
			if c.name == "非严重级不受门约束" {
				it.Level = "高"
			}
			it.XChk = c.xchk
			it.Refute = c.refute
			if err := s.Create(ctx, admin(), "req", it); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, admin(), "req", it.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != c.want {
				t.Errorf("等级应为 %s: %s（xchk=%v）", c.want, got.Level, c.xchk)
			}
			if c.note != "" && !strings.Contains(got.Note, c.note) {
				t.Errorf("Note 应留痕降级原因: %q", got.Note)
			}
			if c.note == "" && strings.Contains(got.Note, "门1未过") {
				t.Errorf("通过门1不应有降级留痕: %q", got.Note)
			}
			if c.note == "" && strings.Contains(got.Note, "门2未过") {
				t.Errorf("通过门2不应有降级留痕: %q", got.Note)
			}
		})
	}
}

// 为什么：降级是「可见的诚实」而非静默改数——审计必须留下 gate1 事件，
// 否则分析人看到「高」却不知道原本报的是「严重」（可解释性=零误报链的一环）。
func TestGate1DowngradeIsAudited(t *testing.T) {
	ctx := context.Background()
	s, l := newSvc()
	it := full()
	it.Level = "严重"
	it.XChk = []string{"rule:R-KEY"}
	if err := s.Create(ctx, admin(), "req", it); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range l.Snapshot() {
		if e.Action == "ledger.gate1_downgrade" && e.Result == audit.ResultAllow {
			found = true
		}
	}
	if !found {
		t.Error("门1 降级必须留审计（ledger.gate1_downgrade）")
	}
}

// answeredRefute 一条已回答的反证（excluded=结论成立）——供门1门2 全过用例使用。
func answeredRefute() []RefuteCheck {
	return []RefuteCheck{{Claim: "命中值为示例占位符", Outcome: "excluded", Evidence: "rule:R-KEY"}}
}

// ---- V-10 零误报门2（反证搜索 / AX-3 / 设计方案 §7.1 门2）----

// 为什么：行业实证（LLM 从零找漏洞误报率 >90%）的另一半=确定性命中也常是假阳性
// （示例值/测试夹具/停用资产）。门2 强制「先回答什么能否定它，再谈严重」：
// 没回答不得给最高级；反证成立必须降级并留痕（不可复现/被否定不得标严重=一票否决⑨）。
func TestSevereRequiresRefuteSearch(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		refute []RefuteCheck
		want   string
		note   string
	}{
		{"无反证记录", nil, "高", "门2未过"},
		{"反证未回答", []RefuteCheck{{Claim: "命中值为示例占位符"}}, "高", "门2未过"},
		{"反证已排除", []RefuteCheck{{Claim: "命中值为示例占位符", Outcome: "excluded", Evidence: "rule:R-KEY"}}, "严重", ""},
		{"多条中一条已排除也算已排除", []RefuteCheck{
			{Claim: "文件位于夹具目录", Outcome: "excluded", Evidence: "path!=fixture"},
			{Claim: "资产已停用", Outcome: "excluded", Evidence: "status=在用"},
		}, "严重", ""},
		{"反证成立=结论被否定", []RefuteCheck{{Claim: "命中值为示例占位符", Outcome: "confirmed", Evidence: "value=example_key"}}, "中", "反证成立"},
		{"confirmed 优先于 excluded", []RefuteCheck{
			{Claim: "文件位于夹具目录", Outcome: "excluded", Evidence: "path"},
			{Claim: "命中值为示例占位符", Outcome: "confirmed", Evidence: "value=example_key"},
		}, "中", "反证成立"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newSvc()
			it := full()
			it.ID = "L-g2-" + c.name
			it.Level = "严重"
			it.XChk = []string{"rule:R-KEY", "rule:R-SRCPKG"} // 门1 先过，隔离测门2
			it.Refute = c.refute
			if err := s.Create(ctx, admin(), "req", it); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, admin(), "req", it.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != c.want {
				t.Errorf("等级应为 %s: %s", c.want, got.Level)
			}
			if c.note != "" && !strings.Contains(got.Note, c.note) {
				t.Errorf("Note 应留痕: %q（期望含 %q）", got.Note, c.note)
			}
			if c.note == "" && strings.Contains(got.Note, "门2未过") {
				t.Errorf("通过门2不应有降级留痕: %q", got.Note)
			}
		})
	}
}

// 为什么：降级必须是「可见的诚实」——审计留 gate2 事件，否则看到「高/中」的人
// 不知道原始申报是「严重」（可解释性=零误报链的一环，与门1 同口径）。
func TestGate2DowngradeIsAudited(t *testing.T) {
	ctx := context.Background()
	s, l := newSvc()
	it := full()
	it.Level = "严重"
	it.XChk = []string{"rule:R-KEY", "rule:R-SRCPKG"}
	it.Refute = []RefuteCheck{{Claim: "命中值为示例占位符", Outcome: "confirmed", Evidence: "value=example_key"}}
	if err := s.Create(ctx, admin(), "req", it); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range l.Snapshot() {
		if e.Action == "ledger.gate2_downgrade" && e.Result == audit.ResultAllow {
			found = true
		}
	}
	if !found {
		t.Error("门2 降级必须留审计（ledger.gate2_downgrade）")
	}
}

// ---- S-2 零误报门3（验证记录 / AX-3+AX-4）----

// 为什么：闭环必须可验证——「已闭环」不再是内存里的状态字，而是一条带方法/结果/
// 证据引用/操作人的记录。无证据引用的 reproduced=不可回溯的主张，一律拒绝（C-5）。
func TestVerifyRequiresEvidenceAndRecords(t *testing.T) {
	ctx := context.Background()
	s, l := newSvc()
	it := full()
	if err := s.Create(ctx, admin(), "c", it); err != nil {
		t.Fatal(err)
	}
	// reproduced 无证据引用 → ErrInvalid（400 类），且不留半记录
	if _, err := s.Verify(ctx, admin(), "v", it.ID, Verification{Method: MethodManual, Result: ResultReproduced}); err == nil {
		t.Error("reproduced 无证据引用必须拒绝")
	}
	got, _ := s.Get(ctx, admin(), "g", it.ID)
	if len(got.Verifs) != 0 || got.Status != StatusOpen {
		t.Errorf("拒绝的验证不得留记录/改状态: %+v", got)
	}
	// 非法方法/结果 → ErrInvalid
	if _, err := s.Verify(ctx, admin(), "v", it.ID, Verification{Method: "oracle", Result: ResultReproduced, EvidenceRef: "e://x"}); err == nil {
		t.Error("非法方法必须拒绝")
	}
	// manual reproduced + 证据 → 闭环 + 记录（操作人默认取主体）
	rec, err := s.Verify(ctx, admin(), "v", it.ID, Verification{
		Method: MethodManual, Result: ResultReproduced, EvidenceRef: "minio://easm-evidence/verify/x.json", Note: "人工复测通过",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verifier != "u7" || rec.TS.IsZero() {
		t.Errorf("记录应带操作人与时间: %+v", rec)
	}
	got, _ = s.Get(ctx, admin(), "g", it.ID)
	if got.Status != StatusClosed || len(got.Verifs) != 1 || got.Verifs[0].EvidenceRef == "" {
		t.Errorf("闭环+记录不完整: %+v", got)
	}
	// inconclusive → 回退整改中（不得闭环）
	if _, err := s.Verify(ctx, admin(), "v", it.ID, Verification{Method: MethodCrossTool, Result: ResultInconclusive, EvidenceRef: "e://y"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(ctx, admin(), "g", it.ID)
	if got.Status != StatusDoing || len(got.Verifs) != 2 {
		t.Errorf("无法判定应回退整改中且记录累计: %+v", got)
	}
	// 审计留痕
	found := false
	for _, e := range l.Snapshot() {
		if e.Action == "ledger.verify" && e.Result == audit.ResultAllow {
			found = true
		}
	}
	if !found {
		t.Error("验证必须留审计（ledger.verify allow）")
	}
}

// 为什么（ENH-10 边界）：沙箱 PoC 是门3 的正式形态，但未接入时不得以 sandbox 名义
// 闭环——501 fail loud，人工复测（manual）作为 MVP 可用路径同时保留（人在环 AX-5）。
func TestSandboxVerifyRequiresProvider(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc()
	it := full()
	if err := s.Create(ctx, admin(), "c", it); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, admin(), "v", it.ID, Verification{Method: MethodSandbox, Result: ResultReproduced, EvidenceRef: "e://x"}); err != ErrNoVerf {
		t.Errorf("未接入沙箱 provider 应 ErrNoVerf: %v", err)
	}
	// 接入 provider 后：以 provider 产出为权威（调用方声明被覆盖）
	s.SetVerifier(func(context.Context, Item) (Verification, error) {
		return Verification{Method: MethodSandbox, Result: ResultReproduced,
			Verifier: "sandbox-pool-1", EvidenceRef: "minio://easm-evidence/poc/x.bin", Note: "PoC 回连确认"}, nil
	})
	rec, err := s.Verify(ctx, admin(), "v", it.ID, Verification{Method: MethodSandbox, Result: ResultInconclusive, EvidenceRef: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verifier != "sandbox-pool-1" || rec.Result != ResultReproduced || rec.EvidenceRef != "minio://easm-evidence/poc/x.bin" {
		t.Errorf("provider 产出应为权威记录: %+v", rec)
	}
	got, _ := s.Get(ctx, admin(), "g", it.ID)
	if got.Status != StatusClosed || len(got.Verifs) != 1 {
		t.Errorf("沙箱复现成功应闭环: %+v", got)
	}
}
