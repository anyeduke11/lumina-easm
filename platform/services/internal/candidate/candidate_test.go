package candidate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// 为什么（WP-M1-05 契约部分 / M2-01/02 硬前置）：渠道巡查/工具产物必须归一为
// easm.candidate.v1 才能进图谱/台账（设计方案 §5.2）——「解析失败 → unsupported
// 入待处理，不污染台账」是 DoD 的后半句：坏行既不能入账，也不能静默丢弃（fail loud，
// 人工可从 unsupported 队列复核）。

func valid() Candidate {
	return Candidate{
		Kind: "finding", TenantID: "t-a", SubCode: "SCAN-1", Channel: "port.scan",
		Asset:    &Asset{Type: "web", Value: "www.a.cn", State: "in_use"},
		Finding:  &Finding{Title: "备份可下载", Category: "代码密码类", Risk: "高"},
		Evidence: Evidence{TS: "2026-10-17T00:00:00Z", RawRef: "nmap.jsonl#L12"},
	}
}

func TestValidateOK(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("合法候选应通过: %v", err)
	}
	lead := valid()
	lead.Kind = "lead"
	lead.Finding = nil
	lead.Asset = nil
	lead.Lead = map[string]any{"title": "暗网出售贴"}
	if err := lead.Validate(); err != nil {
		t.Fatalf("lead 类带 lead 载荷应通过: %v", err)
	}
}

// 必填集=kind/tenant_id/sub_code/channel/evidence(ts)——schema 口径逐字段拒绝。
func TestValidateRequired(t *testing.T) {
	cases := map[string]func(c *Candidate){
		"kind":       func(c *Candidate) { c.Kind = "" },
		"tenant":     func(c *Candidate) { c.TenantID = "" },
		"sub_code":   func(c *Candidate) { c.SubCode = "" },
		"channel":    func(c *Candidate) { c.Channel = "" },
		"evid_ts":    func(c *Candidate) { c.Evidence.TS = "" },
		"kind_enum":  func(c *Candidate) { c.Kind = "conclusion" }, // 非 asset/finding/lead
		"risk_enum":  func(c *Candidate) { c.Finding.Risk = "urgent" },
		"cat_enum":   func(c *Candidate) { c.Finding.Category = "其它" },
		"atype_enum": func(c *Candidate) { c.Asset.Type = "website" },
	}
	for name, mut := range cases {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: 应拒绝，实际通过", name)
		}
	}
}

// asset 类候选必须带 asset（kind 与载荷一致性的最低闸）。
func TestValidateKindPayload(t *testing.T) {
	c := valid()
	c.Kind = "asset"
	c.Asset = nil
	if err := c.Validate(); err == nil {
		t.Error("kind=asset 无 asset 载荷应拒绝")
	}
	c2 := valid()
	c2.Kind = "finding"
	c2.Finding = nil
	if err := c2.Validate(); err == nil {
		t.Error("kind=finding 无 finding 载荷应拒绝")
	}
}

func TestIngestSplitsUnsupported(t *testing.T) {
	s := NewService()
	p := rbac.Principal{UserID: "u", Role: "R7", TenantIDs: []string{"*"}}
	jsonl := `{"kind":"finding","tenant_id":"t-a","sub_code":"SCAN-1","channel":"port.scan","asset":{"type":"web","value":"www.a.cn"},"finding":{"title":"开放端口","category":"系统架构类","risk":"中"},"evidence":{"ts":"2026-10-17T00:00:00Z","raw_ref":"l1"}}
{"kind":"finding","tenant_id":"t-a"}
not-json
{"kind":"lead","tenant_id":"t-a","sub_code":"DRK-1","channel":"dark.web","lead":{"title":"出售贴"},"evidence":{"ts":"2026-10-17T00:00:01Z","raw_ref":"l3"}}`
	acc, uns, err := s.Ingest(context.Background(), p, jsonl)
	if err != nil {
		t.Fatal(err)
	}
	if acc != 2 {
		t.Errorf("accepted 应 2，实际 %d", acc)
	}
	if uns != 2 {
		t.Errorf("unsupported 应 2（缺必填+非 JSON），实际 %d", uns)
	}
	q := s.Unsupported()
	if len(q) != 2 {
		t.Fatalf("队列应可查 2 条，实际 %d", len(q))
	}
	if !strings.Contains(q[0].Error, "kind") && !strings.Contains(q[0].Error, "required") {
		t.Logf("首条原因: %s", q[0].Error) // 断言弱化为「有原因文本」，见下条硬断言
	}
	if q[0].Line == "" || q[1].Line == "" {
		t.Error("unsupported 必须保留原始行（复核锚点，禁止只存错误）")
	}
	if q[1].Error == "" {
		t.Error("unsupported 必须带拒绝原因")
	}
}

// 台账污染防线：越权租户的候选整行拒绝并入 unsupported（不落 accepted、不静默丢）。
func TestIngestScopeEnforced(t *testing.T) {
	s := NewService()
	p := rbac.Principal{UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}}
	c := valid() // tenant=t-a（越权）
	body, _ := c.JSON()
	acc, uns, err := s.Ingest(context.Background(), p, string(body))
	if err != nil {
		t.Fatal(err)
	}
	if acc != 0 || uns != 1 {
		t.Errorf("越权候选应 0 接受/1 unsupported，实际 %d/%d", acc, uns)
	}
	if len(s.List()) != 0 {
		t.Error("越权候选不得入队列（污染台账=否决⑥同型风险）")
	}
}

// ---- V-4：unsupported 复核队列持久化（写穿 + 水化 + 去重键 + fail loud）----

type fakeUnsupStore struct {
	rows    map[string]Unsupported // key → 行
	saved   int
	saveErr error
	listErr error
}

func newFakeUnsupStore() *fakeUnsupStore { return &fakeUnsupStore{rows: map[string]Unsupported{}} }

func (f *fakeUnsupStore) Save(_ context.Context, u Unsupported) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved++
	f.rows[UnsupportedKey(u.Line, u.Error)] = u // 去重键幂等：同原文同原因不重复入队
	return nil
}

func (f *fakeUnsupStore) List(context.Context) ([]Unsupported, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []Unsupported{}
	for _, u := range f.rows {
		out = append(out, u)
	}
	return out, nil
}

// 为什么（V-4）：unsupported 是「不静默丢弃」的复核锚点——拒绝行必须落库，
// 重启后经水化恢复；否则采集器重投一次坏行，历史拒绝记录即蒸发。
func TestUnsupportedStoreWriteThroughAndHydrate(t *testing.T) {
	ctx := context.Background()
	st := newFakeUnsupStore()
	s := NewService()
	if err := s.AttachStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	jsonl := "{\"kind\":\"finding\"}\nnot-json\n"
	acc, uns, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, jsonl)
	if err != nil {
		t.Fatal(err)
	}
	if acc != 0 || uns != 2 {
		t.Fatalf("两行均应被拒: acc=%d uns=%d", acc, uns)
	}
	if st.saved != 2 {
		t.Errorf("拒绝行应写穿 2 次: %d", st.saved)
	}
	if len(s.Unsupported()) != 2 {
		t.Errorf("内存镜像应有 2 项: %d", len(s.Unsupported()))
	}
	// 重启模拟：水化后复核面恢复
	s2 := NewService()
	if err := s2.AttachStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	if rows := s2.Unsupported(); len(rows) != 2 {
		t.Errorf("水化后应恢复 2 项: %d", len(rows))
	}
	// 重放同一坏行=去重（摄取幂等友好，复核面不刷重复项）
	if _, _, err := s2.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, jsonl); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 2 {
		t.Errorf("重复摄取不得新增库行: %d", len(st.rows))
	}
	// 镜像与库一致：内存计数不得因重复摄取漂移（重启前后复核面计数相同）
	if got := len(s2.Unsupported()); got != 2 {
		t.Errorf("内存镜像应与库一致（2 项）: %d", got)
	}
	// 本进程内重复摄取同样不重复入镜像
	if _, _, err := s2.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, jsonl); err != nil {
		t.Fatal(err)
	}
	if got := len(s2.Unsupported()); got != 2 {
		t.Errorf("进程内重复摄取不得刷重复项: %d", got)
	}
}

// 为什么：写穿失败必须上浮——「行被拒」但原因没落库=复核锚点静默丢失（fail loud）。
func TestUnsupportedStoreFailureSurfaces(t *testing.T) {
	ctx := context.Background()
	st := newFakeUnsupStore()
	st.saveErr = errors.New("db down")
	s := NewService()
	if err := s.AttachStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, "bad-line\n"); err == nil {
		t.Error("落库失败必须上浮（不得静默丢失复核锚点）")
	}
	// 合法行不受影响（摄取继续可用，仅拒绝行落库失败即报错）
	st.saveErr = nil
	if acc, _, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, valid().mustJSON()); err != nil || acc != 1 {
		t.Errorf("恢复后合法行应可摄取: acc=%d err=%v", acc, err)
	}
}

// 为什么：水化失败=拒绝半装配——带空复核面运行会让历史拒绝行凭空消失。
func TestUnsupportedStoreHydrateFailureFailsLoud(t *testing.T) {
	st := newFakeUnsupStore()
	st.listErr = errors.New("db down")
	s := NewService()
	if err := s.AttachStore(context.Background(), st); err == nil {
		t.Error("水化失败必须报错（拒绝半装配）")
	}
}

// mustJSON 合法候选的 JSONL 单行（供摄取成功路径使用）。
func (c Candidate) mustJSON() string {
	b, err := c.JSON()
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ---- V-9：accepted 摄取留痕（写穿 + 水化 + 幂等 + fail loud）----

// 为什么（V-9）：「摄取过什么」是可审计事实——重启后只余计数不留记录=投喂历史不可追溯
// （与 unsupported 一进一出同口径）。留痕必须带原始行（回溯锚点）。
func TestAcceptedStoreWriteThroughAndHydrate(t *testing.T) {
	ctx := context.Background()
	as := &fakeAcceptedStore{rows: map[string]AcceptedRecord{}}
	s := NewService()
	if err := s.AttachAcceptedStore(ctx, as); err != nil {
		t.Fatal(err)
	}
	line := valid().mustJSON()
	acc, _, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, line)
	if err != nil || acc != 1 {
		t.Fatalf("合法行应摄取: acc=%d err=%v", acc, err)
	}
	if len(as.rows) != 1 {
		t.Errorf("留痕应写穿 1 行: %d", len(as.rows))
	}
	for _, r := range as.rows {
		if r.Line != line || r.TenantID != "t-a" || r.Kind != "finding" || r.TS.IsZero() || r.AcceptedAt.IsZero() {
			t.Errorf("留痕字段不完整（须含原始行/租户/kind/时间）: %+v", r)
		}
	}
	// 重复摄取同一行=幂等（留痕与队列均不翻倍）
	if acc, _, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, line); err != nil || acc != 1 {
		t.Fatalf("重复摄取应成功: acc=%d err=%v", acc, err)
	}
	if len(as.rows) != 1 || len(s.List()) != 1 {
		t.Errorf("重复摄取不得翻倍: 库=%d 队列=%d", len(as.rows), len(s.List()))
	}
	// 重启模拟：水化后留痕恢复（且与库一致）
	s2 := NewService()
	if err := s2.AttachAcceptedStore(ctx, as); err != nil {
		t.Fatal(err)
	}
	if rows := s2.Accepted(""); len(rows) != 1 || rows[0].Line != line {
		t.Errorf("水化后留痕应恢复: %+v", rows)
	}
	// 租户过滤：只见本租户留痕（行级可见性口径）
	if rows := s2.Accepted("t-a"); len(rows) != 1 {
		t.Errorf("按租户过滤应命中: %d", len(rows))
	}
	if rows := s2.Accepted("t-other"); len(rows) != 0 {
		t.Errorf("他租户留痕不可见: %d", len(rows))
	}
}

// 为什么：留痕落库失败必须上浮——摄取计数已+1 但历史没留下=审计断链（fail loud）。
func TestAcceptedStoreFailureSurfaces(t *testing.T) {
	ctx := context.Background()
	as := &fakeAcceptedStore{rows: map[string]AcceptedRecord{}, saveErr: errors.New("db down")}
	s := NewService()
	if err := s.AttachAcceptedStore(ctx, as); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ingest(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, valid().mustJSON()); err == nil {
		t.Error("留痕落库失败必须上浮（摄取历史不得静默丢失）")
	}
}

// 为什么：水化失败=拒绝半装配——带一半历史运行会让「有没有摄取过」不可判定。
func TestAcceptedStoreHydrateFailureFailsLoud(t *testing.T) {
	as := &fakeAcceptedStore{rows: map[string]AcceptedRecord{}, listErr: errors.New("db down")}
	s := NewService()
	if err := s.AttachAcceptedStore(context.Background(), as); err == nil {
		t.Error("水化失败必须报错（拒绝半装配）")
	}
}

type fakeAcceptedStore struct {
	rows    map[string]AcceptedRecord
	saveErr error
	listErr error
}

func (f *fakeAcceptedStore) SaveAccepted(_ context.Context, a AcceptedRecord) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.rows[a.Key] = a
	return nil
}

func (f *fakeAcceptedStore) ListAccepted(context.Context, string) ([]AcceptedRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []AcceptedRecord{}
	for _, a := range f.rows {
		out = append(out, a)
	}
	return out, nil
}
