package notice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

type fakeLedgers struct{ items map[string]ledger.Item }

func (f fakeLedgers) Get(_ context.Context, _ rbac.Principal, _, id string) (ledger.Item, error) {
	if i, ok := f.items[id]; ok {
		return i, nil
	}
	return ledger.Item{}, ledger.ErrNotFound
}

// List 实现 notice.ListAll（总结统计面；按 f.Tenant 过滤）。
func (f fakeLedgers) List(_ context.Context, _ rbac.Principal, _ string, fl ledger.Filter) ([]ledger.Item, error) {
	var out []ledger.Item
	for _, i := range f.items {
		if fl.Tenant == "" || i.Tenant == fl.Tenant {
			out = append(out, i)
		}
	}
	return out, nil
}

func item() ledger.Item {
	return ledger.Item{ID: "L-1", Tenant: "t-a", Phase: "P4", Category: "代码密码类",
		Asset: "github.com/x/y", Title: "仓库泄露备份库", Level: "高", Source: "EXT-1/gitleaks",
		Found: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), Action: "删除", Owner: "安全运营",
		Due: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Note: "snapshot_ref=file://ev/1.json",
		Status: ledger.StatusOpen} // 入账默认态（真实 ledger.Create 同口径）
}

func newSvc(now time.Time) (*Service, fakeLedgers) {
	lg := fakeLedgers{items: map[string]ledger.Item{"L-1": item()}}
	s := NewService(NewMemStore(), &audit.MemLog{}, lg)
	s.WithLedgerList(lg) // 总结统计面（生产由 main 注入 ledger.Service）
	s.now = func() time.Time { return now }
	return s, lg
}

// 为什么（FR-LGR-007 验收「通报生成单号与材料」+ CR-002「记录每一次线索通报的目标、
// 材料哈希与时间戳」）：发起通报必须产出可归档的单号（同条目同目标=同单号，幂等）+
// 三要素齐备的记录 + 可回溯材料（固化证据、哈希对得上文本）——缺任一=公安不予受理。
func TestCreateIssueNoticeNumberAndMaterial(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	s, _ := newSvc(now)
	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n.ID, "NB-") {
		t.Errorf("通报单号应 NB-*: %s", n.ID)
	}
	if n.Target != TargetPolice || n.DeadlineH != 24 {
		t.Errorf("公安目标应 24h 时限: %+v", n)
	}
	if n.MaterialHash == "" || len(n.MaterialHash) != 64 {
		t.Errorf("CR-002 材料哈希缺失: %q", n.MaterialHash)
	}
	if n.CreatedAt.IsZero() {
		t.Error("CR-002 时间戳缺失")
	}
	if n.MaterialRef == "" {
		t.Error("材料未固化（不可回溯=通报材料不成立）")
	}
	// 材料内容须含单号/目标/时限/条目要素（通用模板的最低完整面）
	b, err := s.Material(ctx, admin(), "r", "t-a", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, kw := range []string{n.ID, "属地公安机关", "24", "仓库泄露备份库", "github.com/x/y"} {
		if !strings.Contains(b, kw) {
			t.Errorf("材料应含 %q，实际: %s", kw, b)
		}
	}
	// CR-002 材料哈希必须对得上文本（重算比对=「哈希记在单上、文本可独立校验」的闭环；
	// 哈希不内嵌于材料自身，否则自引用不可能成立）
	if got := sha256hex([]byte(b)); got != n.MaterialHash {
		t.Errorf("材料哈希与文本不一致: 记录 %s 重算 %s", n.MaterialHash, got)
	}
	// 幂等重放：同条目同目标=同单号（不产第二个单号——单号即归档键）
	n2, err := s.Create(ctx, admin(), "r2", "t-a", "L-1", TargetPolice)
	if err != nil || n2.ID != n.ID {
		t.Errorf("重放应同单号: %v %+v", err, n2)
	}
	// 同条目另一目标=独立单号（公安 24h 与通报中心 48h 各自跟踪）
	n3, err := s.Create(ctx, admin(), "r3", "t-a", "L-1", TargetCenter)
	if err != nil || n3.ID == n.ID || n3.DeadlineH != 48 {
		t.Errorf("通报中心应独立 48h 单: %v %+v", err, n3)
	}
}

// 为什么（幽灵/跨租户台账不得生成通报=FR-LGR-007 材料真实性的前置）：通报材料里的条目
// 要素来自台账——条目不存在或属他租户时生成通报=向公安提交虚构材料（比不报更严重）。
func TestCreateRejectsGhostAndCrossTenantLedger(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	s, lg := newSvc(now)
	if _, err := s.Create(ctx, admin(), "r", "t-a", "L-GHOST", TargetPolice); !errors.Is(err, ledger.ErrNotFound) {
		t.Errorf("幽灵台账应拒: %v", err)
	}
	lg.items["L-9"] = ledger.Item{ID: "L-9", Tenant: "t-zz", Title: "他租户条目"}
	if _, err := s.Create(ctx, admin(), "r", "t-a", "L-9", TargetPolice); err == nil || !strings.Contains(err.Error(), "租户") {
		t.Errorf("跨租户台账应拒: %v", err)
	}
	// 非法目标=拒（目标枚举=报送对象承诺的两个机构，写错机构=材料无效）
	if _, err := s.Create(ctx, admin(), "r", "t-a", "L-1", "随便某个媒体"); !errors.Is(err, ErrInvalid) {
		t.Errorf("非法目标应 ErrInvalid: %v", err)
	}
}

// 为什么（A-08「通报时限超时后显著标识」P0 验收）：24h/48h 是监管硬时限——未报送且
// 超时的通报必须被显式标出并可筛（催办面）；已录回执后不再算超时（义务已履行）。
func TestOverdueFlagAndReceiptClearsIt(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	s, _ := newSvc(base)
	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	// 时限内（+23h）=未超时
	s.now = func() time.Time { return base.Add(23 * time.Hour) }
	ov, _ := s.Overdue(ctx, admin(), "r", "t-a")
	if len(ov) != 0 {
		t.Errorf("23h 不应判超时: %+v", ov)
	}
	// 超时（+25h）=显著标识 + 可筛
	s.now = func() time.Time { return base.Add(25 * time.Hour) }
	ov, _ = s.Overdue(ctx, admin(), "r", "t-a")
	if len(ov) != 1 || ov[0].ID != n.ID {
		t.Fatalf("25h 应超时标识: %+v", ov)
	}
	list, _ := s.List(ctx, admin(), "r", "t-a", "")
	if len(list) != 1 || !list[0].Overdue {
		t.Errorf("列表项须带 Overdue 标识: %+v", list)
	}
	// 录回执=义务履行，超时标识消失；回执字段只追加，材料哈希/单号/目标不得被改写（CR-002）
	if err := s.MarkReceipt(ctx, admin(), "r", "t-a", n.ID, "公网文〔2026〕123号", s.now()); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get(ctx, admin(), "r", "t-a", n.ID)
	if after.Status != StatusSubmitted || after.ReceiptNo == "" || after.SubmittedAt == nil {
		t.Errorf("回执未生效: %+v", after)
	}
	if ov, _ := s.Overdue(ctx, admin(), "r", "t-a"); len(ov) != 0 {
		t.Errorf("已报送不应再超时: %+v", ov)
	}
	if after.MaterialHash != n.MaterialHash || after.ID != n.ID || after.Target != n.Target {
		t.Error("CR-002 三要素被改写（单号/目标/材料哈希必须锁定）")
	}
	// 重复回填=拒（首份凭证不可被后续覆盖——报送时间是监管时限判定的依据）
	if err := s.MarkReceipt(ctx, admin(), "r2", "t-a", n.ID, "伪造的第二份凭证", s.now()); !errors.Is(err, ErrLocked) {
		t.Errorf("重复回执应 ErrLocked，实际 %v", err)
	}
}

// 为什么（一票否决④延伸 / A-09 同型）：越权主体不得建通报、不得读他租户通报材料与回执——
// 通报材料含泄露事实，跨租户可见=二次泄露；只读角色不得发起通报（写域动作）。
func TestRBACAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	s, _ := newSvc(now)
	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	ro := rbac.Principal{UserID: "u3", Role: "R3", TenantIDs: []string{"*"}}
	outsider := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-zz"}}
	if _, err := s.Create(ctx, ro, "r", "t-a", "L-1", TargetPolice); !errors.Is(err, rbac.ErrForbidden) {
		t.Error("只读角色发起通报应 403")
	}
	// 他租户主体以自身路径引用他方台账：必须拒（真库=ledger 行级闸 ErrCrossTenant；
	// 本替身=notice 自有跨租户关联闸 ErrInvalid「租户」——两者都是拒绝，不得生成材料）
	if _, err := s.Create(ctx, outsider, "r", "t-zz", "L-1", TargetPolice); err == nil ||
		!(errors.Is(err, ErrInvalid) || errors.Is(err, rbac.ErrCrossTenant)) {
		t.Errorf("他方台账引用应拒，实际 %v", err)
	}
	if _, err := s.Get(ctx, outsider, "r", "t-zz", n.ID); !errors.Is(err, ErrNotFound) {
		t.Error("越权主体经自身路径碰他单应 404（不泄露存在性，AX-5）")
	}
	if _, err := s.Material(ctx, outsider, "r", "t-zz", n.ID); !errors.Is(err, ErrNotFound) {
		t.Error("越权主体不得读他方通报材料")
	}
	if err := s.MarkReceipt(ctx, ro, "r", "t-a", n.ID, "x", now); !errors.Is(err, rbac.ErrForbidden) {
		t.Error("只读角色录回执应 403")
	}
}

// 为什么（WP-M2-04 任务项「证据链固化」+ FR-CHN-008/C-5 的交付面）：交给公安的不是
// 一段材料文本，而是**材料 + 逐项可核验证据**的封闭链条——每项须给出 sha256/字节数/后端，
// 且「取不到」必须显式标为 unresolved（不得静默省略=证据链完整性不可造假）。
// 台账证据锚点（note=snapshot_ref=…）与材料 ref 同链；跨租户 ref 一律不读不纳。
func TestChainFreezesEvidenceWithVerifiableHashes(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 台账带采集层证据锚点（collect/darkweb 写入的真实格式）
	raw := []byte("原始 gitleaks 报告（REDACTED）")
	evRef, err := ev.Put(ctx, "ext-scan/t-a/deadbeef.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	lg := fakeLedgers{items: map[string]ledger.Item{"L-1": func() ledger.Item {
		i := item()
		i.Note = "snapshot_ref=" + evRef
		return i
	}()}}
	s := NewService(NewMemStore(), &audit.MemLog{}, lg)
	s.now = func() time.Time { return now }
	s.WithEvidence(ev)

	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := s.Chain(ctx, admin(), "r", "t-a", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Items) != 2 {
		t.Fatalf("证据链应含材料+台账锚点两项: %+v", ch.Items)
	}
	for _, it := range ch.Items {
		if !it.Resolved {
			t.Errorf("证据项未解析（不得进交付包）: %+v", it)
		}
		if len(it.SHA256) != 64 || it.Bytes == 0 {
			t.Errorf("证据项缺可核验哈希/字节数: %+v", it)
		}
	}
	// 台账锚点项哈希必须等于原始字节哈希（可独立复核）
	mat := ch.Items[0]
	if mat.SHA256 != sha256hex([]byte(n.Material)) {
		t.Errorf("材料哈希不符: %s", mat.SHA256)
	}
	var anchor *ChainItem
	for i := range ch.Items {
		if ch.Items[i].Ref == evRef {
			anchor = &ch.Items[i]
		}
	}
	if anchor == nil || anchor.SHA256 != sha256hex(raw) {
		t.Errorf("台账证据锚点哈希不符: %+v", anchor)
	}
	if ch.ContentHash == "" {
		t.Error("交付包缺整链哈希")
	}
	for _, kw := range []string{n.ID, ch.Items[0].SHA256, anchor.SHA256, "证据链"} {
		if !strings.Contains(ch.Text, kw) {
			t.Errorf("交付包文本缺 %q", kw)
		}
	}
}

// 为什么（fail loud 优于静默完整）：证据对象取不到（丢失/后端故障）时，交付包必须
// 把该项标为 unresolved 并带原因——省略=制造「证据齐备」的假象，是通报材料的严重缺陷。
// 跨租户 ref（含他租户路径段）不得被读取或纳入（C-5 在导出面同样生效）。
func TestChainMarksUnresolvedAndSkipsCrossTenantRef(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	ev, _ := evidence.NewFileStore(t.TempDir())
	// 他租户路径下**真实可读**的对象（用 Put 返回的完整 ref）：归属闸一旦失效，
	// 它会被成功读取并标 verified→「应标未解析」断言失败。捕获的是闸本身，非对象缺失副作用。
	otherRef, err := ev.Put(ctx, "ext-scan/t-zz/beefcafe.json", []byte("他租户证据字节"))
	if err != nil {
		t.Fatal(err)
	}
	lg := fakeLedgers{items: map[string]ledger.Item{"L-1": func() ledger.Item {
		i := item()
		i.Note = "snapshot_ref=" + otherRef
		return i
	}(), "L-2": func() ledger.Item {
		i := item()
		i.ID = "L-2"
		i.Note = "snapshot_ref=minio://bucket/ext-scan/t-a/missing.json" // 本租户但不存在
		return i
	}()}}
	s := NewService(NewMemStore(), &audit.MemLog{}, lg)
	s.now = func() time.Time { return now }
	s.WithEvidence(ev)

	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := s.Chain(ctx, admin(), "r", "t-a", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	var bad *ChainItem
	for i := range ch.Items {
		if strings.Contains(ch.Items[i].Ref, "t-zz") {
			bad = &ch.Items[i]
		}
	}
	if bad == nil || bad.Resolved {
		t.Fatal("跨租户 ref 应存在且标未解析")
	}
	if !strings.Contains(bad.Error, "tenant") && !strings.Contains(bad.Error, "租户") {
		t.Errorf("跨租户项须给出拒绝原因: %+v", bad)
	}
	// 交付包文本必须显式出现不可核验项（不得只列可核验项假装完整）
	if !strings.Contains(ch.Text, bad.Ref) || !strings.Contains(ch.Text, "unresolved") {
		t.Errorf("交付包须显式标出 unresolved 项: %s", ch.Text)
	}
	// 本租户但对象缺失 → 同样 unresolved（不得跳过）
	n2, err := s.Create(ctx, admin(), "r", "t-a", "L-2", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	ch2, _ := s.Chain(ctx, admin(), "r", "t-a", n2.ID)
	miss := false
	for _, it := range ch2.Items {
		if !it.Resolved && strings.Contains(it.Ref, "missing.json") {
			miss = true
		}
	}
	if !miss {
		t.Errorf("缺失对象应标 unresolved: %+v", ch2.Items)
	}
	// 越权主体不得导出他租户证据链
	if _, err := s.Chain(ctx, rbac.Principal{Role: "R1", TenantIDs: []string{"t-zz"}}, "r", "t-zz", n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("越权导出应 404: %v", err)
	}
}

// 无证据后端时：材料行内文本仍可核验（notice:// 逻辑 ref 由通报单自身承载），
// 台账外部 ref 标 unresolved——不因降级形态谎称已固化。
func TestChainWithoutEvidenceBackend(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	s, _ := newSvc(now)
	n, err := s.Create(ctx, admin(), "r", "t-a", "L-1", TargetPolice)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := s.Chain(ctx, admin(), "r", "t-a", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	var mat, ext int
	for _, it := range ch.Items {
		if strings.HasPrefix(it.Ref, "notice://") {
			mat++
			if !it.Resolved || it.SHA256 != sha256hex([]byte(n.Material)) {
				t.Errorf("行内材料应可核验: %+v", it)
			}
		}
		if strings.HasPrefix(it.Ref, "file://") || strings.HasPrefix(it.Ref, "minio://") {
			ext++
			if it.Resolved {
				t.Errorf("无证据后端时外部 ref 不得谎称已解析: %+v", it)
			}
		}
	}
	if mat != 1 || ext != 1 {
		t.Errorf("应含行内材料 1 项 + 外部锚点 1 项: %+v", ch.Items)
	}
}

// 为什么（FR-LGR-008/FR-RPT-005「结构完整、可导出」P0 验收的过渡形态）：合规报送总结
// 必须三段齐备（排查发现突出问题/整改措施及成效/长效机制建设）+ 数字与台账事实一致（不虚报）
// + 带哈希可固化（报送版本可追溯）。真实定稿格式=G8-02（过渡=通用模板）。
func TestSummaryReportStructure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	s, _ := newSvc(now)
	rep, err := s.Summary(ctx, admin(), "r", "t-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range []string{"排查发现突出问题", "整改措施及成效", "长效机制建设情况"} {
		if !strings.Contains(rep.Text, sec) {
			t.Errorf("总结缺章节 %q: %s", sec, rep.Text)
		}
	}
	if !strings.Contains(rep.Text, "仓库泄露备份库") {
		t.Error("突出问题章节未反映台账事实")
	}
	if rep.ContentHash == "" || len(rep.ContentHash) != 64 {
		t.Errorf("总结缺内容哈希: %q", rep.ContentHash)
	}
	// 数字一致性：台账 1 条→总结应报 1 条（不虚报、不遗漏）
	if !strings.Contains(rep.Text, "1") {
		t.Error("总结应含台账计数事实")
	}
}
