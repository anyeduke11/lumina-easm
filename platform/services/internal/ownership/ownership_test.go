package ownership

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

func tenant() Identity {
	return Identity{
		Tenant: "t-a", Org: "华东联合数据服务集团有限公司", Short: "华东数服",
		Domains: []string{"hddata.cn"}, CIDRs: []string{"203.0.113.0/24"},
	}
}

// ---- FPStore 持久化（010 落库切片）----

type fakeFPStore struct {
	m       map[string]Fingerprints
	saveErr error
}

func (f *fakeFPStore) List(_ context.Context) (map[string]Fingerprints, error) {
	out := map[string]Fingerprints{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}

func (f *fakeFPStore) Save(ctx context.Context, tenantID string, fp Fingerprints) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.m == nil {
		f.m = map[string]Fingerprints{}
	}
	f.m[tenantID] = fp
	return nil
}

// 为什么（本体落库=暗网归属判定跨重启成立）：基线若只在内存，server 重启后所有暗网样本
// 退化为「基线缺失→全疑似」——巡检链路事实性断裂。写穿必须同步（store 失败=内存镜像
// 不留脏数据，否则 Judge 读到的与库里不一致）；Attach 必须水化（新进程从 PG 恢复判据）。
func TestFPStoreWriteThroughAndHydrate(t *testing.T) {
	ctx := context.Background()
	st := &fakeFPStore{}
	s1 := NewService()
	if err := s1.AttachFPStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetFingerprints(ctx, "t-a", Fingerprints{CertFPs: []string{"AA:BB"}}); err != nil {
		t.Fatal(err)
	}
	if got, ok := st.m["t-a"]; !ok || len(got.CertFPs) != 1 {
		t.Fatalf("基线未写穿到 store: %+v", st.m)
	}
	// 新「进程」= 水化恢复，且 Judge 能消费恢复后的基线
	s2 := NewService()
	if err := s2.AttachFPStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.FingerprintsOf("t-a"); !ok {
		t.Fatal("Attach 未水化既有基线")
	}
	v := s2.Judge(tenant(), "leak.onion", Signals{CertFingerprint: "aabb"})
	if v.Verdict != VerdictOwned {
		t.Errorf("水化基线须可判归属: %+v", v)
	}
	// 写穿失败=fail loud，内存镜像不得先脏（Judge 不可基于未持久化基线出归属）
	s3 := NewService()
	if err := s3.AttachFPStore(ctx, &fakeFPStore{saveErr: errors.New("db down")}); err != nil {
		t.Fatal(err)
	}
	if err := s3.SetFingerprints(ctx, "t-a", Fingerprints{CertFPs: []string{"CC"}}); err == nil {
		t.Error("store 失败应上浮错误")
	}
	if _, ok := s3.FingerprintsOf("t-a"); ok {
		t.Error("store 失败后内存镜像不应写入（与库不一致的判据更危险）")
	}
}

// 无 store（纯内存过渡形态）时 SetFingerprints 行为不变=向后兼容边界。
func TestSetFingerprintsWithoutStore(t *testing.T) {
	s := NewService()
	if err := s.SetFingerprints(context.Background(), "t-a", Fingerprints{PageHashes: []string{"9f"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.FingerprintsOf("t-a"); !ok {
		t.Error("无 store 形态仍须可登记/读取")
	}
}

// 为什么（FR-DSC-010 / PRD R2）：六类判定依据必须逐类可出——证书/WHOIS/备案/页脚/
// IP 反查/关键词共现缺一项，监管复核就少一路证据；且归属态要带依据清单。
func TestVerdictStrongSignals(t *testing.T) {
	s := NewService()
	cases := []struct {
		name   string
		domain string
		sig    Signals
		want   string
	}{
		{"主域即归属", "a.hddata.cn", Signals{}, VerdictOwned},
		{"证书主题匹配", "vpn.other-isp.cn", Signals{CertSubject: "CN=*.华东数服, O=华东联合数据服务集团有限公司"}, VerdictOwned},
		{"备案主体匹配", "newsite.cn", Signals{ICPSubject: "华东联合数据服务集团有限公司"}, VerdictOwned},
		{"WHOIS 组织匹配", "reg.cn", Signals{WhoisOrg: "HuaDong Lianhe Data Service Group Co."}, VerdictSuspect}, // 拼音不在词典 → 弱信号，见下注
		{"IP 在授权网段", "x.cn", Signals{IP: "203.0.113.42"}, VerdictOwned},
		{"页脚含简称", "mirror.cn", Signals{Footer: "© 2026 华东数服 版权所有"}, VerdictOwned},
		{"关键词共现", "misc.cn", Signals{KeywordCooccur: 3}, VerdictSuspect},
		{"无任何信号=无关", "someone-else.com", Signals{}, VerdictUnrelated},
	}
	for _, c := range cases {
		v := s.Judge(tenant(), c.domain, c.sig)
		if v.Verdict != c.want {
			t.Errorf("%s: 期望 %s 实际 %s（依据 %+v）", c.name, c.want, v.Verdict, v.Reasons)
		}
		if v.Verdict == VerdictOwned && (v.Confidence < 0.8 || len(v.Reasons) == 0) {
			t.Errorf("%s: 归属态必须高置信+依据: %+v", c.name, v)
		}
	}
}

// 为什么（一票否决④延伸 / PRD R2「三态置信度+人工复核」）：无关与疑似【不得自动入账】——
// 复核队列是强制路径；归属才放行。队列消费后条目关闭。
func TestReviewQueuePolicy(t *testing.T) {
	ctx := context.Background()
	s := NewService()
	owned := s.Judge(tenant(), "a.hddata.cn", Signals{})
	if queued, err := s.AdmitOrQueue(ctx, "t-a", owned, "x"); err != nil || queued {
		t.Error("归属应直接放行（不入复核队列）")
	}
	if len(s.Queue()) != 0 {
		t.Error("归属不应产生队列项")
	}
	suspect := s.Judge(tenant(), "misc.cn", Signals{KeywordCooccur: 2})
	if queued, err := s.AdmitOrQueue(ctx, "t-a", suspect, "misc.cn"); err != nil || !queued {
		t.Error("疑似必须进复核队列")
	}
	unrel := s.Judge(tenant(), "who-evil.com", Signals{})
	if queued, err := s.AdmitOrQueue(ctx, "t-a", unrel, "who-evil.com"); err != nil || !queued {
		t.Error("无关也必须进复核（不静默丢弃，保留可审计）")
	}
	q := s.Queue()
	if len(q) != 2 || q[0].Domain != "misc.cn" || q[0].Verdict.Verdict != VerdictSuspect {
		t.Errorf("队列内容错误: %+v", q)
	}
	// 人工复核出口：resolve 后出队、审计留痕
	if err := s.Resolve(ctx, q[0].Seq, VerdictOwned, "复核人A"); err != nil {
		t.Error("resolve 应成功")
	}
	if len(s.Queue()) != 1 {
		t.Error("resolve 后应剩 1")
	}
	// 重复复核同一项=ErrQueueNotFound（已复核不可二次覆盖，防回执式改写）
	if err := s.Resolve(ctx, q[0].Seq, VerdictOwned, "复核人B"); err != ErrQueueNotFound {
		t.Errorf("已复核项应 ErrQueueNotFound: %v", err)
	}
}

// WHOIS 中文公司名直配归属；拼音/英文需备案号辅助（MVP 词典=中文字符匹配，误配比漏配更危险——fail loud）。
func TestWhoisChinese(t *testing.T) {
	s := NewService()
	v := s.Judge(tenant(), "reg.cn", Signals{WhoisOrg: "华东联合数据服务集团有限公司"})
	if v.Verdict != VerdictOwned {
		t.Errorf("中文 WHOIS 全称应归属: %+v", v)
	}
}

// 为什么（FR-CHN-005 P0 / M2-02 首小项）：暗网样本常无域名/备案/WHOIS 线索，条款点名的四类
// 资产指纹（证书指纹/页面结构哈希/内部命名规则/数据字段特征）是唯一的归属判定路径。
// 逐类必须可出结论（带置信度+依据）；「无法确认」不得判成「无关」——须进人工复核（验收条款）。
func TestFRCHN005FourFingerprintSignals(t *testing.T) {
	s := NewService()
	s.SetFingerprints(context.Background(), "t-a", Fingerprints{
		CertFPs:       []string{"AA:BB:CC:11:22:33:DD:EE"},
		PageHashes:    []string{"9f2c4e7a1b3d"},
		NamingRules:   []string{"hdws_", "HDDC-"},
		FieldFeatures: []string{"cust_id_no", "acct_bank_code", "inner_emp_mail"},
	})
	cases := []struct {
		name       string
		domain     string
		sig        Signals
		want       string
		wantReason string // 依据清单必须点名所用信号（监管复核可追溯）
	}{
		{"⑨证书指纹一致（格式差异不影响比对）", "onion7x3q.onion",
			Signals{CertFingerprint: "aa-bb-cc-11-22-33-dd-ee"}, VerdictOwned, "证书指纹"},
		{"⑩页面结构哈希一致", "mirror-dark.example",
			Signals{PageStructHash: "9F2C4E7A1B3D"}, VerdictOwned, "页面结构哈希"},
		{"⑪内部命名规则命中≥2", "leak.site",
			Signals{SampleNames: []string{"hdws_user_order", "HDDC-2026-001.xlsx", "readme.txt"}}, VerdictOwned, "内部命名规则"},
		{"⑪单命中=疑似（巧合名不足以定归属）", "leak.site",
			Signals{SampleNames: []string{"hdws_only_one"}}, VerdictSuspect, "内部命名规则"},
		{"⑫数据字段特征命中≥3", "db.dump",
			Signals{DataFields: []string{"id", "cust_id_no", "acct_bank_code", "inner_emp_mail"}}, VerdictOwned, "数据字段特征"},
		{"⑫字段命中 2=疑似", "db.dump",
			Signals{DataFields: []string{"id", "cust_id_no", "acct_bank_code"}}, VerdictSuspect, "数据字段特征"},
		{"四类皆未命中=疑似（非无关，须人工复核）", "someone-else.onion",
			Signals{CertFingerprint: "11:22:33:44:55:66", PageStructHash: "deadbeef",
				SampleNames: []string{"orders.csv"}, DataFields: []string{"user_name", "phone"}}, VerdictSuspect, "未命中"},
	}
	for _, c := range cases {
		v := s.Judge(tenant(), c.domain, c.sig)
		if v.Verdict != c.want {
			t.Errorf("%s: 期望 %s 实际 %s（依据 %+v）", c.name, c.want, v.Verdict, v.Reasons)
		}
		if !containsAnyReason(v.Reasons, c.wantReason) {
			t.Errorf("%s: 依据清单须点名 %q: %+v", c.name, c.wantReason, v.Reasons)
		}
		if v.Verdict == VerdictOwned && v.Confidence < 0.8 {
			t.Errorf("%s: 归属态须高置信: %+v", c.name, v)
		}
	}
}

// 为什么（FR-CHN-005 验收「无法确认进人工复核」+ 一票否决④延伸）：租户未登记指纹基线时，
// 样本携带指纹≠可比对——既不得虚判归属（无基准），也不得判无关（静默丢弃线索）；
// 必须落「疑似+基线缺失」并进复核队列。这是 M2-02 暗网样本入口的安全默认。
func TestFRCHN005MissingBaselineGoesToReview(t *testing.T) {
	s := NewService()
	v := s.Judge(tenant(), "leak.onion", Signals{CertFingerprint: "AA:BB:CC", DataFields: []string{"cust_id_no"}})
	if v.Verdict != VerdictSuspect {
		t.Errorf("无基线时须判疑似（不得虚判归属/不得判无关）: %+v", v)
	}
	if !containsAnyReason(v.Reasons, "基线") {
		t.Errorf("依据须说明基线缺失: %+v", v.Reasons)
	}
	if queued, err := s.AdmitOrQueue(context.Background(), "t-a", v, v.Domain); err != nil || !queued {
		t.Error("疑似必须进人工复核队列")
	}
}

// 为什么（C-6 多租户隔离在一票否决面的延伸）：基线按租户登记，
// 甲租户的证书指纹/字段字典不得成为乙租户样本的归属依据（跨租户串证据=台账污染+泄露面扩大）。
func TestFingerprintBaselinesAreTenantScoped(t *testing.T) {
	s := NewService()
	s.SetFingerprints(context.Background(), "t-a", Fingerprints{CertFPs: []string{"AA:BB:CC"}})
	if _, ok := s.FingerprintsOf("t-b"); ok {
		t.Fatal("t-b 不应有基线（登记按租户隔离）")
	}
	other := Identity{Tenant: "t-b", Org: "别家单位", Short: "别家", Domains: []string{"other.cn"}}
	v := s.Judge(other, "leak.onion", Signals{CertFingerprint: "AA:BB:CC"})
	if v.Verdict == VerdictOwned {
		t.Errorf("跨租户指纹基线不得判归属: %+v", v)
	}
}

func containsAnyReason(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// ---- V-4：复核队列持久化（写穿 + 水化 + 幂等 seq）----

// fakeQueueStore 记录写穿调用；saveErr 用于验证「落库失败必须上浮」。
type fakeQueueStore struct {
	rows    map[int]QueueItem // seq → item（模拟库：仅 pending）
	byKey   map[string]int    // tenant|domain → seq
	next    int
	saved   int
	saveErr error
	listErr error
}

func newFakeQueueStore() *fakeQueueStore {
	return &fakeQueueStore{rows: map[int]QueueItem{}, byKey: map[string]int{}}
}

func (f *fakeQueueStore) key(it QueueItem) string { return it.Tenant + "|" + it.Domain }

func (f *fakeQueueStore) List(context.Context) ([]QueueItem, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []QueueItem{}
	for seq, q := range f.rows {
		q.Seq = seq // 列权威：水化回读以库 seq 覆盖快照（与 pgstore List 同口径）
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func (f *fakeQueueStore) Save(_ context.Context, it QueueItem) (int, error) {
	if f.saveErr != nil {
		return 0, f.saveErr
	}
	f.saved++
	it.Seq = 0                             // 快照不携带序号（列权威）——与 pgstore 实现同口径
	if seq, ok := f.byKey[f.key(it)]; ok { // 幂等：同租户同域保留原 seq
		f.rows[seq] = it
		return seq, nil
	}
	f.next++
	f.rows[f.next] = it
	f.byKey[f.key(it)] = f.next
	return f.next, nil
}

func (f *fakeQueueStore) Resolve(_ context.Context, seq int, toVerdict, reviewer string, ts time.Time) error {
	it, ok := f.rows[seq]
	if !ok {
		return ErrQueueNotFound
	}
	it.Verdict.Verdict = toVerdict
	it.Verdict.Reasons = append(it.Verdict.Reasons, "人工复核 "+reviewer+" → "+toVerdict)
	it.Verdict.TS = ts
	delete(f.rows, seq) // 已复核=出 pending（库中另存 resolved 行，fake 简化为删除）
	return nil
}

// 为什么（V-4）：复核队列是「不静默丢弃」的锚点——装配 PG 后疑似/无关样本必须写穿，
// 且重启后经水化恢复（否则暗网样本判过一次就蒸发=污染防线断裂）。
func TestQueueStoreWriteThroughAndHydrate(t *testing.T) {
	ctx := context.Background()
	st := newFakeQueueStore()
	s := NewService()
	if err := s.AttachQueueStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	v := s.Judge(tenant(), "leak.onion", Signals{KeywordCooccur: 2})
	queued, err := s.AdmitOrQueue(ctx, "t-a", v, "leak.onion")
	if err != nil || !queued {
		t.Fatalf("疑似应入队且落库: queued=%v err=%v", queued, err)
	}
	if st.saved != 1 {
		t.Errorf("应写穿 1 次: %d", st.saved)
	}
	if q := s.Queue(); len(q) != 1 || q[0].Tenant != "t-a" || q[0].Seq != 1 {
		t.Errorf("队列项须带租户与稳定 seq: %+v", q)
	}
	// 同租户同域重复入队=刷新判决保留原 seq（复核编号稳定，不刷出第二项）
	v2 := s.Judge(tenant(), "leak.onion", Signals{CertFingerprint: "AA:BB"})
	if _, err := s.AdmitOrQueue(ctx, "t-a", v2, "leak.onion"); err != nil {
		t.Fatal(err)
	}
	if q := s.Queue(); len(q) != 1 || q[0].Seq != 1 {
		t.Errorf("重复入队不得新增项/改 seq: %+v", q)
	}
	// 重启模拟：新 Service 水化后队列与序号延续
	s2 := NewService()
	if err := s2.AttachQueueStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	if q := s2.Queue(); len(q) != 1 || q[0].Domain != "leak.onion" || q[0].Tenant != "t-a" {
		t.Errorf("水化后队列应恢复: %+v", q)
	}
	v3 := s2.Judge(tenant(), "other.onion", Signals{})
	if _, err := s2.AdmitOrQueue(ctx, "t-a", v3, "other.onion"); err != nil {
		t.Fatal(err)
	}
	if q := s2.Queue(); len(q) != 2 || q[1].Seq != 2 {
		t.Errorf("水化后新项 seq 应延续: %+v", q)
	}
	// 复核出口：落库 + 内存同步出队
	if err := s2.Resolve(ctx, 1, VerdictOwned, "复核人A"); err != nil {
		t.Fatal(err)
	}
	if q := s2.Queue(); len(q) != 1 || q[0].Seq != 2 {
		t.Errorf("复核后应出队: %+v", q)
	}
}

// 为什么：库失败必须上浮——「样本已判疑似」但队列没落库=静默丢弃线索（fail loud）。
func TestQueueStoreFailureSurfaces(t *testing.T) {
	ctx := context.Background()
	st := newFakeQueueStore()
	st.saveErr = errors.New("db down")
	s := NewService()
	if err := s.AttachQueueStore(ctx, st); err != nil {
		t.Fatal(err)
	}
	v := s.Judge(tenant(), "leak.onion", Signals{})
	if _, err := s.AdmitOrQueue(ctx, "t-a", v, "leak.onion"); err == nil {
		t.Error("落库失败必须上浮（不得静默丢弃复核锚点）")
	}
	if len(s.Queue()) != 0 {
		t.Error("库未接受时内存镜像不得留下队列项")
	}
	// 序号回退：失败项不占用 seq（否则库中出现空洞编号）
	v2 := s.Judge(tenant(), "next.onion", Signals{})
	if _, err := s.AdmitOrQueue(ctx, "t-a", v2, "next.onion"); err == nil {
		t.Error("store 仍故障应继续上浮")
	}
	st.saveErr = nil
	if _, err := s.AdmitOrQueue(ctx, "t-a", v2, "next.onion"); err != nil {
		t.Fatal(err)
	}
	if q := s.Queue(); len(q) != 1 || q[0].Seq != 1 {
		t.Errorf("故障项不得占用 seq: %+v", q)
	}
}

// 为什么：水化失败=拒绝半装配——带空队列运行会让全部暗网样本退化为「无人复核」。
func TestQueueStoreHydrateFailureFailsLoud(t *testing.T) {
	st := newFakeQueueStore()
	st.listErr = errors.New("db down")
	s := NewService()
	if err := s.AttachQueueStore(context.Background(), st); err == nil {
		t.Error("水化失败必须报错（拒绝半装配）")
	}
}
