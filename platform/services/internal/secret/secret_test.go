package secret

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// ---- 测试替身（确定性、零外部依赖）----

type memGraph struct {
	ents map[string]graph.Entity
	rels map[string]graph.Relation
}

func newMemGraph() *memGraph {
	return &memGraph{ents: map[string]graph.Entity{}, rels: map[string]graph.Relation{}}
}

func (m *memGraph) UpsertEntity(_ context.Context, e graph.Entity) (graph.Entity, bool, error) {
	m.ents[e.Fingerprint] = e
	return e, true, nil
}

func (m *memGraph) UpsertRelation(_ context.Context, r graph.Relation) error {
	m.rels[r.FromFP+"|"+r.Type+"|"+r.ToFP] = r
	return nil
}

func (m *memGraph) Entities(_ context.Context, tenant string) ([]graph.Entity, error) {
	out := make([]graph.Entity, 0, len(m.ents))
	for _, e := range m.ents {
		if e.Tenant == tenant {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

func (m *memGraph) relCount(typ string) int {
	n := 0
	for k := range m.rels {
		if strings.Contains(k, "|"+typ+"|") {
			n++
		}
	}
	return n
}

func (m *memGraph) entCount(kind string) int {
	n := 0
	for _, e := range m.ents {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

type fakeProber struct {
	status int
	err    error
	calls  int
}

func (f *fakeProber) Probe(_ context.Context, _ Entry) (ProbeResult, error) {
	f.calls++
	if f.err != nil {
		return ProbeResult{}, f.err
	}
	return ProbeResult{Reached: true, Status: f.status}, nil
}

func ent(rule, loc, snippet, src string) Entry {
	return Entry{Tenant: "t-a", Rule: rule, Location: loc, Snippet: snippet,
		Masked: maskOf(snippet), SourceFP: src, ProbeURL: "https://api.example.com/v1/ping",
		EvidenceRef: "evi:test"}
}

// 形状样本密钥（AKIA 前缀 + 20 位；非真实凭据，仅形状样本）
const awsKey = "AKIAIOSFODNN7EXAMPLE"

// 为什么（FR-CHN-002）：已知前缀密钥格式必须被识别为「格式有效」，
// 未探活=unverifiable（不是 valid——不把「看起来像」当「可用」上报）。
func TestVerifyKnownPrefixIsFormatOK(t *testing.T) {
	g := newMemGraph()
	s := New().WithGraph(g)
	got, err := s.Verify(context.Background(), "t-a", []Entry{ent(RuleKey, "app/config.js#L12", awsKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("应返回 1 条判定: %d", len(got))
	}
	v := got[0]
	if v.Format != FormatOK {
		t.Errorf("格式应 ok: %s", v.Format)
	}
	if v.Status != StatusUnverifiable || v.Method != MethodFormat {
		t.Errorf("未探活应 unverifiable/format: %s/%s", v.Status, v.Method)
	}
	if !v.Graphed {
		t.Error("判定应入图（可度量、可复核）")
	}
	if v.Linked {
		t.Error("未确证有效不得连接攻击路径边")
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "AKIA") {
		t.Errorf("依据须可解释（含前缀名）: %+v", v.Reasons)
	}
}

// 为什么：占位符是最常见假阳性——必须在探活前以「上下文」判定挡掉（省外呼、降误报）。
func TestVerifyPlaceholderIsRefutedByContext(t *testing.T) {
	s := New().WithGraph(newMemGraph())
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleHardcode, "app/config.js#L3", "changeme", "")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != StatusInvalid || got[0].Method != MethodContext {
		t.Errorf("占位符应 invalid/context: %s/%s", got[0].Status, got[0].Method)
	}
}

// 为什么（对齐 collect 侧 refuteByPath）：示例/测试路径命中的「密钥」几乎全是夹具，
// 且上下文判定先于格式判定（路径证据强于字符串形状）。
func TestVerifyTestPathIsRefutedBeforeFormat(t *testing.T) {
	s := New().WithGraph(newMemGraph())
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleKey, "internal/testdata/seed.sql#L8", awsKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != StatusInvalid || got[0].Method != MethodContext {
		t.Errorf("测试路径应 invalid/context: %s/%s", got[0].Status, got[0].Method)
	}
}

// 为什么：形状不符（长度不足）不得蒙混为「可能有效」——格式闸是分母净化的第一道。
func TestVerifyShortKeyIsFormatInvalid(t *testing.T) {
	s := New().WithGraph(newMemGraph())
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleKey, "app/config.js#L12", "AKIA1234", "")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Format != FormatInvalid || got[0].Status != StatusInvalid {
		t.Errorf("长度不足应 invalid: %s/%s", got[0].Format, got[0].Status)
	}
}

// 为什么（FR-CHN-002 验收「仅上报验证为可用的凭据」）：探活四结局必须各自可区分，
// 且网络/超时结局=unverifiable（不可达不等于有效，也不等于无效）。
func TestVerifyProbeOutcomes(t *testing.T) {
	cases := []struct {
		status int
		err    error
		want   string
	}{
		{200, nil, StatusValid},
		{401, nil, StatusRevoked},
		{404, nil, StatusInvalid},
		{0, errors.New("dial timeout"), StatusUnverifiable},
	}
	for _, c := range cases {
		p := &fakeProber{status: c.status, err: c.err}
		s := New().WithGraph(newMemGraph()).WithProber(p)
		got, err := s.Verify(context.Background(), "t-a",
			[]Entry{ent(RuleKey, "app/config.js#L12", awsKey, "")})
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Status != c.want {
			t.Errorf("探活 %d/%v 应 %s，实际 %s", c.status, c.err, c.want, got[0].Status)
		}
		if got[0].Method != MethodProbe {
			t.Errorf("探活结局的方法应为 probe: %s", got[0].Method)
		}
		if p.calls != 1 {
			t.Errorf("探活调用次数异常: %d", p.calls)
		}
	}
}

// 为什么（FR-CHN-002 + M3-B 边供给）：只有验证为可用的凭据才连接攻击路径边——
// 否则路径推演会拿「疑似密钥」编造不可处置的攻击链（M3-B 登记缺口的闭合条件）。
func TestVerifyLinksOnlyValidCredentials(t *testing.T) {
	g := newMemGraph()
	// 预置来源实体（域名资产已入图，边才有锚点）
	if _, _, err := g.UpsertEntity(context.Background(), graph.Entity{
		Tenant: "t-a", Kind: graph.KindDomain, Fingerprint: "dom:e.example.cn",
		Props: map[string]string{"value": "e.example.cn"}, InScope: true,
	}); err != nil {
		t.Fatal(err)
	}
	p := &fakeProber{status: 200}
	s := New().WithGraph(g).WithProber(p)
	got, err := s.Verify(context.Background(), "t-a", []Entry{
		ent(RuleKey, "app/config.js#L12", awsKey, "dom:e.example.cn"),          // 有效 → 连边
		ent(RuleKey, "docs/readme.md#L2", "AKIASHORTKEY1", "dom:e.example.cn"), // 长度不足 → 不连边
	})
	if err != nil {
		t.Fatal(err)
	}
	linked := 0
	for _, v := range got {
		if v.Linked {
			linked++
		}
		if !v.Graphed {
			t.Error("全部判定均应入图（度量分母）")
		}
	}
	if linked != 1 {
		t.Errorf("仅有效凭据应连边: %d", linked)
	}
	if g.entCount(graph.KindCredential) != 2 {
		t.Errorf("两条判定均应落为 Credential 实体: %d", g.entCount(graph.KindCredential))
	}
	if g.relCount(graph.RelLeaks) != 1 {
		t.Errorf("leaks 边应仅 1 条: %d", g.relCount(graph.RelLeaks))
	}
}

// 为什么：源实体不在图内时不造边（不伪造来源）——宁可不连，也不让路径凭空出现。
func TestVerifyNoEdgeWhenSourceMissing(t *testing.T) {
	g := newMemGraph()
	p := &fakeProber{status: 200}
	s := New().WithGraph(g).WithProber(p)
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleKey, "app/config.js#L12", awsKey, "dom:not-in-graph.cn")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Linked {
		t.Error("源实体缺失时不得连边（不伪造来源）")
	}
	if g.relCount(graph.RelLeaks) != 0 {
		t.Error("不应产生 leaks 边")
	}
}

// 为什么（FR-CHN-002 验收核心）：形状对但**没有验证为可用**的凭据（未外呼/外呼不可判定）
// 绝不能连攻击路径边——「看起来像密钥」若被当成可用凭据上报，就是 FR-CHN-002 要卡的误报。
func TestVerifyUnverifiableNeverLinks(t *testing.T) {
	g := newMemGraph()
	if _, _, err := g.UpsertEntity(context.Background(), graph.Entity{
		Tenant: "t-a", Kind: graph.KindDomain, Fingerprint: "dom:e.example.cn",
		Props: map[string]string{"value": "e.example.cn"}, InScope: true,
	}); err != nil {
		t.Fatal(err)
	}
	// 无外呼 provider：形状正确但不可验证
	s := New().WithGraph(g)
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleKey, "app/config.js#L12", awsKey, "dom:e.example.cn")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != StatusUnverifiable {
		t.Fatalf("未外呼应 unverifiable: %s", got[0].Status)
	}
	if got[0].Linked {
		t.Error("未验证为可用不得连边（不把疑似密钥当可用凭据上报）")
	}
	if g.relCount(graph.RelLeaks) != 0 {
		t.Error("不应产生 leaks 边")
	}
}

// 为什么（FR-CHN-002 误报率 ≤10% 可度量）：度量必须给出分母与分子，
// 且口径写进响应（不让人拿单一比率冒充「误报率达标」）。
func TestMetricsRatesAreComputed(t *testing.T) {
	g := newMemGraph()
	p := &fakeProber{status: 200}
	s := New().WithGraph(g).WithProber(p)
	if _, err := s.Verify(context.Background(), "t-a", []Entry{
		ent(RuleKey, "a.js#L1", awsKey, ""),                      // valid（探活 200）
		ent(RuleKey, "b.js#L1", "AKIA1234", ""),                  // invalid（长度）
		ent(RuleHardcode, "c.js#L1", "changeme", ""),             // invalid（占位）
		ent(RuleKey, "d.js#L1", "tok_abcdefghijklmnopqrstu", ""), // unverifiable（无已知前缀）
	}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Metrics(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if m.Total != 4 {
		t.Fatalf("总数应为 4（全部判定入图）: %d", m.Total)
	}
	if m.ByStatus[StatusValid] != 1 || m.ByStatus[StatusInvalid] != 2 || m.ByStatus[StatusUnverifiable] != 1 {
		t.Errorf("状态分布不符: %+v", m.ByStatus)
	}
	if m.Probed != 1 || m.ProbeConfirmed != 1 {
		t.Errorf("探活统计不符: attempted=%d confirmed=%d", m.Probed, m.ProbeConfirmed)
	}
	if m.FPRate < 0.49 || m.FPRate > 0.51 {
		t.Errorf("误报率应 ≈0.5（2/4）: %f", m.FPRate)
	}
	if m.ValidRate < 0.24 || m.ValidRate > 0.26 {
		t.Errorf("有效率应 ≈0.25（1/4）: %f", m.ValidRate)
	}
	if m.Basis == "" {
		t.Error("度量须带口径说明（否则比率不可解读）")
	}
}

// 为什么（NFR-SEC：密钥不落明文）：判定结果不得回显原始密钥串。
func TestVerdictDoesNotLeakSecret(t *testing.T) {
	s := New().WithGraph(newMemGraph())
	got, err := s.Verify(context.Background(), "t-a",
		[]Entry{ent(RuleKey, "app/config.js#L12", awsKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), awsKey) {
		t.Errorf("判定结果泄露原始密钥: %s", b)
	}
	if got[0].Masked == awsKey || !strings.Contains(got[0].Masked, "****") {
		t.Errorf("脱敏形态不符: %s", got[0].Masked)
	}
}

// 为什么（闭合 M3-B 登记缺口）：M3-B 交付时图谱只有 resolves_to 一种边（Top5 恒空），
// 本包是边供给方——验证为可用的凭据必须产出可推演的 1 跳攻击路径（否则 Top5 无意义）。
func TestVerifyFeedsAttackPathGraph(t *testing.T) {
	gms := graph.NewMemStore()
	gs := graph.NewService(gms)
	if _, _, err := gs.UpsertEntity(context.Background(), graph.Entity{
		Tenant: "t-a", Kind: graph.KindDomain, Fingerprint: "dom:e.example.cn",
		Props: map[string]string{"value": "e.example.cn"}, InScope: true,
	}); err != nil {
		t.Fatal(err)
	}
	s := New().WithGraph(gs).WithProber(&fakeProber{status: 200})
	if _, err := s.Verify(context.Background(), "t-a", []Entry{{
		Rule: RuleKey, Location: "app/config.js#L12", Snippet: awsKey,
		ProbeURL: "https://api.example.com/v1", SourceFP: "dom:e.example.cn",
	}}); err != nil {
		t.Fatal(err)
	}
	paths, err := graph.NewMemPath(gms).TopPaths(context.Background(), "t-a", 5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range paths {
		if p.FromFP == "dom:e.example.cn" && p.ToKind == graph.KindCredential && p.Hops == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("验证为可用的凭据应产出 1 跳攻击路径（Top5 可消费）: %+v", paths)
	}
}

// 为什么（AX-3 可复现）：同输入两次验证须完全一致（ID 与判定不随时序/遍历顺序漂移）。
func TestVerifyDeterministic(t *testing.T) {
	in := func() []Entry {
		return []Entry{
			ent(RuleKey, "a.js#L1", awsKey, ""),
			ent(RuleHardcode, "b.js#L2", "changeme", ""),
		}
	}
	s1 := New().WithGraph(newMemGraph())
	s2 := New().WithGraph(newMemGraph())
	g1, err := s1.Verify(context.Background(), "t-a", in())
	if err != nil {
		t.Fatal(err)
	}
	g2, err := s2.Verify(context.Background(), "t-a", in())
	if err != nil {
		t.Fatal(err)
	}
	for i := range g1 {
		if g1[i].ID != g2[i].ID || g1[i].Status != g2[i].Status || g1[i].Method != g2[i].Method {
			t.Errorf("第 %d 条判定不确定: %+v vs %+v", i, g1[i], g2[i])
		}
	}
	if g1[0].ID == "" || g1[0].ID == g1[1].ID {
		t.Errorf("判定 ID 应稳定且区分条目: %s / %s", g1[0].ID, g1[1].ID)
	}
}
