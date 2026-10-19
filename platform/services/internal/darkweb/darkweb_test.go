package darkweb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// ---- 测试替身 ----

type fakeValidator struct{ err error }

func (f fakeValidator) Validate(context.Context, string) error { return f.err }

type fakeLedger struct {
	created map[string]int
	dupAll  bool
}

func (f *fakeLedger) Create(_ context.Context, _ rbac.Principal, _ string, i ledger.Item) error {
	if f.created == nil {
		f.created = map[string]int{}
	}
	if f.dupAll || f.created[i.ID] > 0 {
		return ledger.ErrDuplicate
	}
	f.created[i.ID]++
	return nil
}

func adminPrincipal() rbac.Principal {
	return rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}
}

func ownedIdentity(own *ownership.Service) ownership.Identity {
	own.SetFingerprints(context.Background(), "t-a", ownership.Fingerprints{CertFPs: []string{"AA:BB:CC"}})
	return ownership.Identity{Tenant: "t-a", Org: "华东数服集团", Short: "华东数服", Domains: []string{"hddata.cn"}}
}

func ownedSample(id string) Sample { // 证书指纹命中基线=归属
	return Sample{ID: id, Domain: id + ".onion", Marketplace: "暗市", PostURL: "http://" + id + ".onion/p",
		CapturedAt: "2026-10-17T00:00:00Z", RawText: "数据样本 " + id, CertFingerprint: "AA:BB:CC",
		SampleRecords: 100, IDMin: 1, IDMax: 5000}
}

// 为什么（M2-02 全链 + 一票否决④延伸）：非归属（无指纹/不匹配）样本必须被拦在复核队列外，
// 绝不进线索包/台账——否则污染公安通报材料。归属样本才走完量级→链路→包固化→入账。
func TestInspectOnlyOwnedLeadsEnterPackage(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	cands := candidate.NewService()
	led := &fakeLedger{}
	dir := t.TempDir()
	ev, err := evidence.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(cands, led, fakeValidator{}, own, ev)

	samples := []Sample{
		ownedSample("S1"),
		ownedSample("S2"),
		{ID: "S3", Domain: "evil.onion", Marketplace: "暗市", PostURL: "http://evil.onion/p",
			CapturedAt: "2026-10-17T00:00:00Z", RawText: "无关样本", DataFields: []string{"random"}}, // 无匹配信号
	}
	res, err := svc.Inspect(context.Background(), adminPrincipal(), "req1", "t-a", id, samples)
	if err != nil {
		t.Fatal(err)
	}
	if res.Samples != 3 || res.Owned != 2 || res.Queued != 1 {
		t.Errorf("归属/复核分流错误: %+v", res)
	}
	if len(own.Queue()) != 1 {
		t.Errorf("非归属须入复核队列，实际 %d", len(own.Queue()))
	}
	if res.Accepted != 2 {
		t.Errorf("仅归属样本进 lead 候选，实际 accepted=%d", res.Accepted)
	}
	if res.NewLedger != 2 {
		t.Errorf("仅归属样本入账，实际 new_ledger=%d", res.NewLedger)
	}
	if res.ContentHash == "" || res.PackageID == "" {
		t.Errorf("线索包须有 content_hash + package_id: %+v", res)
	}
	if !strings.HasPrefix(res.EvidenceRef, "file://") {
		t.Errorf("线索包应固化证据并回填 ref: %q", res.EvidenceRef)
	}
	// 量级仍为区间（跨 2 归属样本聚合，绝不单点）
	if res.Scale.High <= res.Scale.Low {
		t.Errorf("线索包规模须区间: %+v", res.Scale)
	}
}

// 为什么（FR-CHN-005 硬前置消费面）：归属判定依赖的租户指纹基线缺失时，样本判疑似→进复核，
// 线索包不产出——巡检不得绕过归属闸强行出包（图谱/通报防污染的第二道闸）。
func TestInspectNoBaselineNoPackage(t *testing.T) {
	own := ownership.NewService() // 未登记基线
	id := ownership.Identity{Tenant: "t-a", Org: "X", Domains: []string{"hddata.cn"}}
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, nil)
	res, err := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id,
		[]Sample{ownedSample("S1")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Owned != 0 || res.PackageID != "" || res.Queued != 1 {
		t.Errorf("无基线=全疑似、不出包: %+v", res)
	}
}

// 为什么（三重闸：一票否决⑥延伸）：写权限/租户作用域/授权总闸任一不过=巡检入口即拒，
// 绝不允许跨租户或窗外巡检出包。
func TestInspectGateOrder(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, nil)
	// 越权租户
	if _, err := svc.Inspect(context.Background(), rbac.Principal{Role: "R7", TenantIDs: []string{"t-zz"}}, "r", "t-a", id, []Sample{ownedSample("S1")}); !errors.Is(err, rbac.ErrCrossTenant) {
		t.Errorf("跨租户应拒: %v", err)
	}
	// 无写权限
	if _, err := svc.Inspect(context.Background(), rbac.Principal{Role: "R3", TenantIDs: []string{"*"}}, "r", "t-a", id, []Sample{ownedSample("S1")}); !errors.Is(err, rbac.ErrForbidden) {
		t.Errorf("无写权限应拒: %v", err)
	}
	// 授权总闸失败
	svc2 := New(candidate.NewService(), &fakeLedger{}, fakeValidator{err: errors.New("no_valid_scope")}, own, nil)
	if _, err := svc2.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id, []Sample{ownedSample("S1")}); err == nil {
		t.Error("授权总闸失败应上浮")
	}
}

// 为什么（C-5 重放幂等）：同输入两次巡检=同 content_hash、台账去重翻倍被挡——线索包不可
// 因重扫产生内容漂移（监管材料必须逐次一致）。
func TestInspectReplayIdempotent(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	cands := candidate.NewService()
	led := &fakeLedger{}
	ev, _ := evidence.NewFileStore(t.TempDir())
	svc := New(cands, led, fakeValidator{}, own, ev)
	samples := []Sample{ownedSample("S1"), ownedSample("S2")}
	r1, _ := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id, samples)
	r2, _ := svc.Inspect(context.Background(), adminPrincipal(), "r2", "t-a", id, samples)
	if r1.ContentHash != r2.ContentHash {
		t.Errorf("重放 content_hash 须一致: %s vs %s", r1.ContentHash, r2.ContentHash)
	}
	if r2.NewLedger != 0 || r2.Dup != 2 {
		t.Errorf("重放台账去重应 dup=2/new=0: %+v", r2)
	}
}

// 为什么（截图取证要素锚定）：提供截图字节时，线索包 item 必须带 screenshot_ref（非空），
// 指向已固化的不可变对象——公安通报的「截图」要素不能只是声明。
func TestInspectScreenshotRef(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	ev, _ := evidence.NewFileStore(t.TempDir())
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, ev)
	sm := ownedSample("S1")
	sm.Screenshot = []byte("\x89PNG\r\n\x1a\nshotbytes")
	res, err := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id, []Sample{sm})
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	// 读取包内容验证 item.screenshot_ref 非空
	b, err := ev.Get(context.Background(), res.EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	var pkg LeadPackage
	if err := json.Unmarshal(b, &pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Items) != 1 || pkg.Items[0].ScreenshotRef == "" {
		t.Errorf("截图须固化并回填 item.screenshot_ref: %+v", pkg.Items)
	}
}

// 为什么（FR-CHN-005 消费面）：暗网样本的四类归属信号必须从样本被真实提取并喂给
// ownership.Judge——提取错字段（如把收款地址当证书指纹）归属判定就会失真。
func TestExtractSignalsMapsFourFingerprints(t *testing.T) {
	s := Sample{
		CertFingerprint: "AA:BB:CC:11:22", PageStructHash: "9f2c4e7a",
		SampleNames: []string{"hdws_order", "HDDC-1.xlsx"},
		DataFields:  []string{"cust_id_no", "acct_bank_code"},
	}
	sig := ExtractSignals(s)
	if sig.CertFingerprint != "AA:BB:CC:11:22" || sig.PageStructHash != "9f2c4e7a" {
		t.Errorf("证书指纹/页面哈希提取错误: %+v", sig)
	}
	if len(sig.SampleNames) != 2 || len(sig.DataFields) != 2 {
		t.Errorf("命名/字段提取错误: %+v", sig)
	}
}

// 为什么（FR-CHN-006 验收「不以单点数字作结论」P1）：泄露规模必须由样本结构反推为
// 区间+置信度——ID 连续性、字段完整度任一可用都要收窄区间；全部线索缺失时宁可给保守
// 倍率区间，也绝不输出单点数字（监管不接受「就是 100 万条」这种无依据硬数字）。
func TestEstimateScaleIsRangeNeverPoint(t *testing.T) {
	// ① ID 连续跨度 > 样本记录：外推上限=跨度
	e := EstimateScale(Sample{SampleRecords: 800, IDMin: 1, IDMax: 50000, FieldTotal: 20, FieldFilled: 18})
	if !(e.Low <= 800 && e.High >= 50000) {
		t.Errorf("ID 连续性应外推 [800,50000]，实际 [%d,%d]", e.Low, e.High)
	}
	if !strings.Contains(e.Method, "ID") {
		t.Errorf("依据须点名 ID 连续性: %s", e.Method)
	}
	if e.High <= e.Low {
		t.Error("必须为区间（High>Low）")
	}

	// ② 无任何结构线索（无 ID、无字段总数）：保守倍率区间，仍非单点
	e2 := EstimateScale(Sample{SampleRecords: 50})
	if e2.High <= e2.Low {
		t.Errorf("无线索也须给区间（非单点）: [%d,%d]", e2.Low, e2.High)
	}
	if e2.Confidence >= 0.7 {
		t.Errorf("无线索置信度应偏低，实际 %.2f", e2.Confidence)
	}

	// ③ 字段完整度影响置信度：同记录数下，完整度高 → 置信度高
	full := EstimateScale(Sample{SampleRecords: 100, FieldTotal: 10, FieldFilled: 10})
	partial := EstimateScale(Sample{SampleRecords: 100, FieldTotal: 10, FieldFilled: 2})
	if !(full.Confidence > partial.Confidence) {
		t.Errorf("字段完整度应提升置信度: full=%.2f partial=%.2f", full.Confidence, partial.Confidence)
	}

	// ④ 空样本记录=无效估计（不虚报规模）
	zero := EstimateScale(Sample{})
	if zero.Low != 0 || zero.High != 0 {
		t.Errorf("无样本记录规模应为 0: [%d,%d]", zero.Low, zero.High)
	}

	// ⑤ 样本恰好铺满 ID 跨度：区间仍不得塌成单点
	tight := EstimateScale(Sample{SampleRecords: 1000, IDMin: 1, IDMax: 1000})
	if tight.High <= tight.Low {
		t.Errorf("铺满跨度仍须非单点（验收条款）: [%d,%d]", tight.Low, tight.High)
	}
}

// 为什么（FR-CHN-007「聚类发布者身份、收款地址、文案模板，还原交易链路」P1）：
// 同一泄露事件常由同一卖家/同一收款地址/同一广告模板分发到多个帖子——共享任一键即
// 属同一链路（连通分量）；无共享属性者各自独立成链。链路是线索包的「交易关系」面。
func TestClusterChainsGroupsBySharedKeys(t *testing.T) {
	samples := []Sample{
		{ID: "A", Publisher: "darkseller", WalletAddr: "", AdTemplate: "t1"},
		{ID: "B", Publisher: "", WalletAddr: "1BTCabc", AdTemplate: "t1"}, // 与 A 共享模板 t1
		{ID: "C", Publisher: "", WalletAddr: "1BTCabc", AdTemplate: ""},   // 与 B 共享收款地址
		{ID: "D", Publisher: "someone", WalletAddr: "", AdTemplate: ""},   // 独立
	}
	chains := ClusterChains(samples)
	byMember := map[string]string{} // sampleID -> chainID
	for _, c := range chains {
		for _, m := range c.Members {
			byMember[m] = c.ID
		}
	}
	if byMember["A"] != byMember["B"] || byMember["B"] != byMember["C"] {
		t.Errorf("A/B/C 应同链（模板+收款地址传递闭合），实际 %+v", byMember)
	}
	if byMember["A"] == byMember["D"] {
		t.Error("D 无共享属性，应独立成链")
	}
	// 合并依据（LinkedBy）须点名促成聚类的共享键值，供链路表可追溯
	var ac *Chain
	for i, c := range chains {
		if c.Members[0] == "A" {
			ac = &chains[i]
		}
	}
	if ac == nil || !strings.Contains(strings.Join(ac.LinkedBy, ","), "t1") {
		t.Errorf("链路须记录共享键 t1 作为合并依据: %+v", ac)
	}
}

// 为什么（FR-CHN-008 P0「按取证要求固化样本哈希、截图、时间戳与来源」+「可直接用于公安
// 通报」）：线索包每一条 item 都必须四要素齐备且样本哈希对得上原文（sha256 可复核），
// 缺任一项=线索包一次过率不达标；ContentHash 为整包规范 JSON 的哈希（防篡改基线）。
func TestBuildPackageForensicFourElements(t *testing.T) {
	owned := []Sample{
		{ID: "S1", Domain: "leak1.onion", Marketplace: "市场X", PostURL: "http://leak1.onion/p/1",
			CapturedAt: "2026-10-17T00:00:00Z", RawText: "客户数据 10 万条 打包出",
			Screenshot: []byte("\x89PNG\r\n\x1a\nfakebytes")},
	}
	items := BuildPackageItems(owned, map[string]string{}, nil) // 无 ev 后端：截图 ref 留空
	if len(items) != 1 {
		t.Fatalf("应 1 条 item")
	}
	it := items[0]
	wantHash := sha256hex([]byte("客户数据 10 万条 打包出"))
	if it.SampleHash != wantHash {
		t.Errorf("样本哈希须=原文 sha256: got %s want %s", it.SampleHash, wantHash)
	}
	if it.Source == "" || it.PostURL == "" || it.CapturedAt == "" || it.SampleHash == "" {
		t.Errorf("取证四要素（哈希/时间戳/来源/URL）须齐备: %+v", it)
	}
	if it.ScreenshotRef != "" {
		t.Error("无证据后端时截图 ref 应为空（不伪造锚点）")
	}
}

// ---- Store 持久化（010 落库切片）----

type fakePkgStore struct {
	m       map[string]LeadPackage // package_id → 包
	saveErr error
}

func (f *fakePkgStore) SavePackage(_ context.Context, pkg LeadPackage) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.m == nil {
		f.m = map[string]LeadPackage{}
	}
	if _, dup := f.m[pkg.PackageID]; dup {
		return nil // WORM 首次语义（与 010 的 ON CONFLICT DO NOTHING 同契约）
	}
	f.m[pkg.PackageID] = pkg
	return nil
}

func (f *fakePkgStore) ListPackages(_ context.Context, tenant string) ([]LeadPackage, error) {
	var out []LeadPackage
	for _, p := range f.m {
		if p.TenantID == tenant {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakePkgStore) GetPackage(_ context.Context, tenant, id string) (LeadPackage, bool, error) {
	p, ok := f.m[id]
	if !ok || p.TenantID != tenant {
		return LeadPackage{}, false, nil
	}
	return p, true, nil
}

// 为什么（通报材料=可复查的持久事实）：线索包只固化在证据对象存储时，「这个租户有哪些包、
// 包内容是什么」无结构化查询面；落库后新进程（重启/worker）可按租户列举与取回整包。
// 持久化失败必须 fail loud 中止——证据对象已写而库未写=材料存在但不可检索（半状态比不产出更糟）。
func TestInspectPersistsPackageAndReadableAcrossProcesses(t *testing.T) {
	st := &fakePkgStore{}
	own := ownership.NewService()
	id := ownedIdentity(own)
	ev, _ := evidence.NewFileStore(t.TempDir())
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, ev)
	svc.AttachStore(st)
	if _, err := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id,
		[]Sample{ownedSample("S1"), ownedSample("S2")}); err != nil {
		t.Fatal(err)
	}
	if len(st.m) != 1 {
		t.Fatalf("线索包未写穿到 store: %d", len(st.m))
	}
	var pkgID string
	for k := range st.m {
		pkgID = k
	}
	// 新「进程」=同 store 可检索 + 取回整包（items 齐备）
	svc2 := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, ownership.NewService(), nil)
	svc2.AttachStore(st)
	list, err := svc2.ListPackages(context.Background(), "t-a")
	if err != nil || len(list) != 1 || list[0].PackageID != pkgID {
		t.Fatalf("跨进程按租户列举失败: %v %+v", err, list)
	}
	got, ok, err := svc2.GetPackage(context.Background(), "t-a", pkgID)
	if !ok || err != nil || len(got.Items) != 2 || got.ContentHash == "" {
		t.Errorf("取回整包不完整: ok=%v err=%v %+v", ok, err, got)
	}
	// 跨租户不可取回（租户闸在端口层同样成立）
	if _, ok, _ := svc2.GetPackage(context.Background(), "t-zz", pkgID); ok {
		t.Error("跨租户不得取回他方线索包")
	}
}

// 落库失败=巡检整体失败（fail loud：禁止「材料出了但查不到」的半状态静默放行）。
func TestInspectStoreFailureAborts(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, nil)
	svc.AttachStore(&fakePkgStore{saveErr: errors.New("db down")})
	_, err := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id, []Sample{ownedSample("S1")})
	if err == nil {
		t.Fatal("store 失败应上浮中止巡检")
	}
	if !strings.Contains(err.Error(), "线索包") {
		t.Errorf("错误应点名线索包持久化: %v", err)
	}
}

// 无 store（纯内存过渡形态）：包仍可列/取，重放同 package_id 不重复计。
func TestInspectMemoryFallbackPackages(t *testing.T) {
	own := ownership.NewService()
	id := ownedIdentity(own)
	svc := New(candidate.NewService(), &fakeLedger{}, fakeValidator{}, own, nil)
	samples := []Sample{ownedSample("S1")}
	r1, err := svc.Inspect(context.Background(), adminPrincipal(), "r", "t-a", id, samples)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Inspect(context.Background(), adminPrincipal(), "r2", "t-a", id, samples); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListPackages(context.Background(), "t-a")
	if err != nil || len(list) != 1 || list[0].PackageID != r1.PackageID {
		t.Errorf("内存回退应可按租户列举且重放不重复: %v %+v", err, list)
	}
	if _, ok, err := svc.GetPackage(context.Background(), "t-a", r1.PackageID); !ok || err != nil {
		t.Error("内存回退 GetPackage 失败")
	}
}

// ---- FR-CHN-007：线索包对外导出面（leadpackage:export）----

// 为什么（对外交付物）：导出文本必须确定性（同包同字节=AX-3 可独立复核），且
// 归属/量级/链路/取证四要素齐备——通报材料缺要素=退件风险（G8-02 交叠）。
func TestRenderPackageMDDeterministic(t *testing.T) {
	pkg := LeadPackage{PackageID: "LPK-abc123def456", TenantID: "t-a", GeneratedAt: "2026-10-17T00:00:00Z",
		ContentHash: "sha256:feed", EvidenceRef: "minio://easm-evidence/t-a/x.tar",
		Items: []LeadItem{{SampleID: "S1", Source: "暗市", PostURL: "http://s1.onion/p",
			CapturedAt: "2026-10-17T00:00:00Z", SampleHash: "h1", Verdict: "owned", Confidence: 0.9}},
		Chains: []Chain{{ID: "C1", Members: []string{"S1", "S2"}, LinkedBy: []string{"发布者"}, Size: 2}},
		Scale:  ScaleEstimate{Low: 100, High: 5000, Confidence: 0.56, Method: "ID 连续性外推"}}
	md1, md2 := RenderPackageMD(pkg), RenderPackageMD(pkg)
	if md1 != md2 {
		t.Fatal("同包两次渲染必须逐字节一致（确定性）")
	}
	for _, want := range []string{"LPK-abc123def456", "100–5000", "ID 连续性外推", "C1", "S1", "S2",
		"发布者", "h1", "sha256:feed", "minio://easm-evidence/t-a/x.tar", "0.9", "http://s1.onion/p"} {
		if !strings.Contains(md1, want) {
			t.Errorf("导出面缺要素 %q", want)
		}
	}
	if strings.Contains(md1, "S3") {
		t.Error("包外条目不得出现在导出材料（归属闸边界）")
	}
}
