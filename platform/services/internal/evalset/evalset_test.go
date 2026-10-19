package evalset

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// ---- 夹具 ----

// stubSubject 固定预言：指标数学用确定性夹具，不依赖判敏规则细节（评测口径与被测对象解耦）。
type stubSubject struct {
	pred     map[string]bool
	evidence map[string]string
	fail     map[string]error
}

func (s stubSubject) Name() string { return "stub" }

func (s stubSubject) Judge(_ context.Context, sm Sample) (bool, string, error) {
	if err, ok := s.fail[sm.Text]; ok {
		return false, "", err
	}
	return s.pred[sm.Text], s.evidence[sm.Text], nil
}

func newSvc(t *testing.T, th *Thresholds) *Service {
	t.Helper()
	svc := New(NewMemStore())
	if th != nil {
		svc = svc.WithThresholds(*th)
	}
	return svc
}

func mustAdd(t *testing.T, svc *Service, tenant string, pairs map[string]bool) []Sample {
	t.Helper()
	in := make([]SampleInput, 0, len(pairs))
	for txt, exp := range pairs {
		in = append(in, SampleInput{Kind: KindSens, Text: txt, Expected: exp})
	}
	_, out, err := svc.AddSamples(context.Background(), tenant, in, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- 样本与去重 ----

func TestAddSamplesDeterministicAndIdempotent(t *testing.T) {
	svc := newSvc(t, nil)
	in := []SampleInput{{Kind: KindSens, Text: "AKIA 秘钥样本", Expected: true}}
	added, out, err := svc.AddSamples(context.Background(), "t-a", in, "u1")
	if err != nil || added != 1 || len(out) != 1 {
		t.Fatalf("首次入集期望 added=1: %v %v %v", added, out, err)
	}
	if !strings.HasPrefix(out[0].ID, "EV-") || out[0].Source != SourceManual || out[0].ExpectedBy != "u1" {
		t.Fatalf("样本 ID/来源/标注人不符: %+v", out[0])
	}
	added2, out2, _ := svc.AddSamples(context.Background(), "t-a", in, "u1")
	if added2 != 0 || out2[0].ID != out[0].ID {
		t.Fatalf("重复入集应幂等（同 ID 不重复）: added=%d id=%s vs %s", added2, out2[0].ID, out[0].ID)
	}
	// 期望标签不同=不同的标注事实，是新样本（不静默覆盖已有标注）
	in3 := []SampleInput{{Kind: KindSens, Text: "AKIA 秘钥样本", Expected: false}}
	added3, _, _ := svc.AddSamples(context.Background(), "t-a", in3, "u2")
	if added3 != 1 {
		t.Fatalf("标签相反应作为新样本入集: added=%d", added3)
	}
}

func TestAddSamplesValidation(t *testing.T) {
	svc := newSvc(t, nil)
	if _, _, err := svc.AddSamples(context.Background(), "t-a", []SampleInput{{Kind: KindSens, Text: "x"}}, ""); err == nil {
		t.Error("缺标注人应拒绝（人在环，标注可追溯）")
	}
	if _, _, err := svc.AddSamples(context.Background(), "t-a", []SampleInput{{Kind: KindSens, Text: "  "}}, "u1"); err == nil {
		t.Error("空文本应拒绝")
	}
	if _, _, err := svc.AddSamples(context.Background(), "t-a", []SampleInput{{Kind: "other", Text: "x", Expected: true}}, "u1"); err == nil {
		t.Error("不支持的评价对象 kind 应拒绝（骨架=判敏面，不冒充研判面）")
	}
}

// ---- 判敏引擎作为首个评测对象（确定性，AX-2）----

func TestClassifySubjectJudges(t *testing.T) {
	sub := NewClassifySubject(classify.New())
	ok, ev, err := sub.Judge(context.Background(), Sample{Text: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg=="})
	if err != nil || !ok || !strings.Contains(ev, "R-PRIVKEY") {
		t.Fatalf("私钥样本应命中且证据含规则编号: %v %q %v", ok, ev, err)
	}
	ok2, ev2, _ := sub.Judge(context.Background(), Sample{Text: "今日天气晴朗，适合外出"})
	if ok2 || ev2 == "" {
		t.Fatalf("良性样本应不命中且留依据（evidence 空串=幻觉计入口）: %v %q", ok2, ev2)
	}
}

// ---- 评测运行与指标（手算对账）----

func fixtureFive(t *testing.T, svc *Service) {
	t.Helper()
	mustAdd(t, svc, "t-a", map[string]bool{"s1": true, "s2": true, "s3": true, "s4": false, "s5": false})
}

func TestRunMetricsHandComputed(t *testing.T) {
	svc := newSvc(t, nil)
	fixtureFive(t, svc)
	// 预言：TP=2(s1,s3) FN=1(s2) TN=1(s4) FP=1(s5)
	stub := stubSubject{pred: map[string]bool{"s1": true, "s2": false, "s3": true, "s4": false, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"}}
	run, err := svc.Run(context.Background(), "t-a", stub)
	if err != nil {
		t.Fatal(err)
	}
	if run.Subject != "stub" || run.Total != 5 {
		t.Fatalf("运行元数据不符: %+v", run)
	}
	c := run.Confusion
	if c.TP != 2 || c.FP != 1 || c.FN != 1 || c.TN != 1 {
		t.Fatalf("混淆矩阵期望 2/1/1/1，实际 %+v", c)
	}
	// P=R=F1=2/3=0.6667；acc=3/5=0.6；误报率=FP/(TP+FP)=1/3=0.3333（四舍五入 4 位）
	if run.Precision != 0.6667 || run.Recall != 0.6667 || run.F1 != 0.6667 || run.Accuracy != 0.6 || run.FPRate != 0.3333 {
		t.Fatalf("指标与手算不符: P=%v R=%v F1=%v acc=%v fpr=%v", run.Precision, run.Recall, run.F1, run.Accuracy, run.FPRate)
	}
	if run.Kappa != nil || run.KappaCover != 0 {
		t.Fatalf("无二次标注时 κ 必须为 nil（不冒充一致性）: %v", run.Kappa)
	}
	if run.Gate.Allow {
		t.Fatalf("默认阈值下（样本 5<30、F1 0.667<0.90）不得放量: %+v", run.Gate)
	}
	if len(run.Skipped) != 0 {
		t.Fatalf("不应有跳过: %+v", run.Skipped)
	}
}

func TestRunGateAllowWhenWithinThresholds(t *testing.T) {
	th := Thresholds{F1Min: 0.6, FPRateMax: 0.34, KappaMin: 0, HallucinationMax: 0, MinSamples: 5}
	svc := newSvc(t, &th)
	fixtureFive(t, svc)
	stub := stubSubject{pred: map[string]bool{"s1": true, "s2": false, "s3": true, "s4": false, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"}}
	run, err := svc.Run(context.Background(), "t-a", stub)
	if err != nil {
		t.Fatal(err)
	}
	if !run.Gate.Allow || len(run.Gate.Reasons) != 0 {
		t.Fatalf("阈值内应放行: %+v", run.Gate)
	}
}

func TestRunKappaHandComputed(t *testing.T) {
	svc := newSvc(t, nil)
	samples := mustAdd(t, svc, "t-a", map[string]bool{
		"k1": true, "k2": true, "k3": true, "k4": true, "k5": true,
		"k6": false, "k7": false, "k8": false, "k9": false, "k10": false,
	})
	// 二次标注：前 8 个与期望一致，后 2 个（期望=false）改标 true
	// rater2 分布 T=7 F=3，rater1 T=5 F=5，po=0.8，pe=0.5*0.7+0.5*0.3=0.5 → κ=0.6
	byID := map[string]Sample{}
	for _, s := range samples {
		byID[s.Text] = s
	}
	for i, txt := range []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"} {
		if _, err := svc.Relabel(context.Background(), "t-a", byID[txt].ID, "u2", i < 5, ""); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = svc.Relabel(context.Background(), "t-a", byID["k9"].ID, "u2", true, "")
	_, _ = svc.Relabel(context.Background(), "t-a", byID["k10"].ID, "u2", true, "")
	stub := stubSubject{} // 预测全 false：κ 只关心标注一致性，与预测无关
	run, err := svc.Run(context.Background(), "t-a", stub)
	if err != nil {
		t.Fatal(err)
	}
	if run.Kappa == nil || *run.Kappa != 0.6 {
		t.Fatalf("κ 期望 0.6，实际 %v", run.Kappa)
	}
	if run.KappaCover != 10 {
		t.Fatalf("κ 覆盖数期望 10，实际 %d", run.KappaCover)
	}
}

func TestRunSkipsFailedJudgement(t *testing.T) {
	svc := newSvc(t, nil)
	fixtureFive(t, svc)
	stub := stubSubject{
		pred:     map[string]bool{"s1": true, "s3": true, "s4": false, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"},
		fail:     map[string]error{"s2": context.DeadlineExceeded},
	}
	run, err := svc.Run(context.Background(), "t-a", stub)
	if err != nil {
		t.Fatal(err)
	}
	if run.Total != 4 || len(run.Skipped) != 1 || run.Skipped[0].SampleID == "" {
		t.Fatalf("判定失败样本应如实单列且不计入指标: total=%d skipped=%+v", run.Total, run.Skipped)
	}
	if run.Confusion.TP != 2 || run.Confusion.FN != 0 {
		t.Fatalf("跳过样本不得混入混淆矩阵: %+v", run.Confusion)
	}
}

func TestRunNoSamplesErr(t *testing.T) {
	svc := newSvc(t, nil)
	if _, err := svc.Run(context.Background(), "t-a", stubSubject{}); err != ErrNoSamples {
		t.Fatalf("空评测集应报 ErrNoSamples，实际 %v", err)
	}
}

func TestRunHallucinationRate(t *testing.T) {
	svc := newSvc(t, nil)
	fixtureFive(t, svc)
	// 预测阳性 3 条，其中 2 条无证据 → 幻觉率 2/3（AI 面口径：无证据支持的正面结论占比）
	stub := stubSubject{pred: map[string]bool{"s1": true, "s2": true, "s3": true, "s4": false, "s5": false},
		evidence: map[string]string{"s3": "R-X"}}
	run, err := svc.Run(context.Background(), "t-a", stub)
	if err != nil {
		t.Fatal(err)
	}
	if run.HallucinationRate != 0.6667 {
		t.Fatalf("幻觉率期望 0.6667，实际 %v", run.HallucinationRate)
	}
}

// ---- 反馈门禁（指标不达标不放量；无记录 fail closed）----

func TestGateFailClosedWithoutRun(t *testing.T) {
	svc := newSvc(t, nil)
	_, d, err := svc.Check(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("无评测记录必须 fail closed（不放量）")
	}
	if !strings.Contains(strings.Join(d.Reasons, "；"), "无评测记录") {
		t.Fatalf("fail closed 原因应如实说明: %+v", d)
	}
}

func TestGateReturnsLatestRunDecision(t *testing.T) {
	svc := newSvc(t, nil)
	fixtureFive(t, svc)
	stub := stubSubject{pred: map[string]bool{"s1": true, "s2": false, "s3": true, "s4": false, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"}}
	if _, err := svc.Run(context.Background(), "t-a", stub); err != nil {
		t.Fatal(err)
	}
	run, d, err := svc.Check(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || d.Allow != run.Gate.Allow {
		t.Fatalf("Check 应返回最近一次运行及其门禁判定: %+v %+v", run.ID, d)
	}
	found := false
	for _, r := range d.Reasons {
		if strings.Contains(r, "F1") {
			found = true
		}
	}
	if d.Allow || !found {
		t.Fatalf("门禁原因应点名 F1 不达标: %+v", d)
	}
}

// 为什么（G8-01 换配置即生效）：门禁按当前阈值口径重算，历史 run.Gate 仅是运行时快照——
// 口径变紧时旧快照不得继续充当放行依据。
func TestGateRecomputesWithCurrentThresholds(t *testing.T) {
	st := NewMemStore()
	svc := New(st)
	fixtureFive(t, svc)
	stub := stubSubject{pred: map[string]bool{"s1": true, "s2": false, "s3": true, "s4": false, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"}}
	if _, err := svc.Run(context.Background(), "t-a", stub); err != nil {
		t.Fatal(err)
	}
	_, d0, _ := svc.Check(context.Background(), "t-a")
	if d0.Allow || d0.ThresholdSrc != DefaultThresholdSource {
		t.Fatalf("默认口径下应不放量且标注来源: %+v", d0)
	}
	// 同一存储、放宽阈值（模拟 G8-01 定稿换配置）：重算后应放行
	lax := New(st).WithThresholds(Thresholds{F1Min: 0.6, FPRateMax: 0.6, KappaMin: 0, HallucinationMax: 0, MinSamples: 5})
	_, d1, err := lax.Check(context.Background(), "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if !d1.Allow || d1.ThresholdSrc != "env（EASM_EVAL_THRESHOLDS）" {
		t.Fatalf("当前口径重算应放行且标注 env 来源: %+v", d1)
	}
}

func TestRunsListNewestFirst(t *testing.T) {
	svc := newSvc(t, nil)
	fixtureFive(t, svc)
	stub := stubSubject{pred: map[string]bool{"s1": true, "s3": true, "s5": true},
		evidence: map[string]string{"s1": "R-X", "s3": "R-X", "s5": "R-X"}}
	r1, _ := svc.Run(context.Background(), "t-a", stub)
	time.Sleep(2 * time.Millisecond)
	r2, _ := svc.Run(context.Background(), "t-a", stub)
	if r1.ID == r2.ID {
		t.Fatal("两次运行应不同 ID")
	}
	rs, _ := svc.Runs(context.Background(), "t-a", 10)
	if len(rs) != 2 || rs[0].ID != r2.ID {
		t.Fatalf("运行历史应最新在前: %+v", rs)
	}
}

// ---- 误报/复测回流（FR-VRF-004：闭环结论回流为评测样本）----

func refluxFixture() []ledger.Item {
	now := time.Now()
	return []ledger.Item{
		// 反证成立 → 误报样本（expected=false）
		{ID: "L-1", Tenant: "t-a", Phase: "P3", Category: "代码密码类", Title: "示例路径命中 AKIA 私钥",
			Level: "中", Source: "P3/Dirsearch", Action: "删除", Owner: "运维部", Found: now, Due: now.Add(24 * time.Hour),
			Refute: []ledger.RefuteCheck{{Claim: "命中值为示例占位符", Outcome: "confirmed", Evidence: "testdata/demo.sql"}}},
		// 最近一次复测 refuted → 误报样本
		{ID: "L-2", Tenant: "t-a", Phase: "P1", Category: "系统架构类", Title: "备份文件可下载",
			Level: "高", Source: "P1/Google", Action: "删除", Owner: "安全部", Found: now, Due: now.Add(24 * time.Hour),
			Verifs: []ledger.Verification{{Method: "manual", Result: "refuted", Verifier: "u1", TS: now}}},
		// 最近一次复测 reproduced → 真阳性样本（expected=true）
		{ID: "L-3", Tenant: "t-a", Phase: "P2", Category: "代码密码类", Title: "gitleaks 命中 ghp_ 令牌",
			Level: "严重", Source: "P2/Fofa", Action: "删除", Owner: "运维部", Found: now, Due: now.Add(24 * time.Hour),
			Verifs: []ledger.Verification{{Method: "manual", Result: "reproduced", Verifier: "u1", EvidenceRef: "evi://L-3", TS: now}}},
		// 复测记录先 refuted 后 reproduced → 以最近为准（真阳性）
		{ID: "L-4", Tenant: "t-a", Phase: "P1", Category: "代码密码类", Title: "数据库 dump 泄露",
			Level: "高", Source: "P1/Google", Action: "删除", Owner: "运维部", Found: now, Due: now.Add(24 * time.Hour),
			Verifs: []ledger.Verification{
				{Method: "manual", Result: "refuted", Verifier: "u1", TS: now.Add(-time.Hour)},
				{Method: "manual", Result: "reproduced", Verifier: "u2", EvidenceRef: "evi://L-4", TS: now}}},
		// 无反证结论、无复测记录 → 无回流信号，跳过（不猜标签）
		{ID: "L-5", Tenant: "t-a", Phase: "P1", Category: "系统架构类", Title: "后台入口暴露",
			Level: "高", Source: "P1/Google", Action: "下线", Owner: "运维部", Found: now, Due: now.Add(24 * time.Hour)},
		// 最近一次复测 inconclusive（无法判定）→ 同样无回流信号（不把存疑当真阳性）
		{ID: "L-6", Tenant: "t-a", Phase: "P1", Category: "系统架构类", Title: "测试数据入库疑似泄露",
			Level: "中", Source: "P1/Google", Action: "下线", Owner: "运维部", Found: now, Due: now.Add(24 * time.Hour),
			Verifs: []ledger.Verification{{Method: "manual", Result: "inconclusive", Verifier: "u1", TS: now}}},
	}
}

func TestRefluxRules(t *testing.T) {
	svc := newSvc(t, nil)
	res, err := svc.Reflux(context.Background(), "t-a", refluxFixture(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 4 || len(res.Samples) != 4 {
		t.Fatalf("回流期望 4 条（L-5 无信号跳过）: %+v", res)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("无信号条目（L-5 无记录 / L-6 inconclusive）应跳过并留痕: %+v", res.Skipped)
	}
	for _, sk := range res.Skipped {
		if sk.LedgerID != "L-5" && sk.LedgerID != "L-6" {
			t.Fatalf("意外跳过项: %+v", sk)
		}
	}
	want := map[string]bool{"L-1": false, "L-2": false, "L-3": true, "L-4": true}
	for _, s := range res.Samples {
		if s.Source != SourceReflux || s.LedgerID == "" || s.ExpectedBy != "u1" || s.Kind != KindSens {
			t.Fatalf("回流样本元数据不符: %+v", s)
		}
		if w, ok := want[s.LedgerID]; !ok || s.Expected != w {
			t.Fatalf("L-4 期望标签不符（%s=%v，期望 %v）", s.LedgerID, s.Expected, w)
		}
	}
	// 幂等：同一批台账重放不重复入集
	res2, _ := svc.Reflux(context.Background(), "t-a", refluxFixture(), "u1")
	if res2.Added != 0 {
		t.Fatalf("重复回流应幂等: %+v", res2)
	}
}

// ---- 阈值解析（配置注入面；非法装载即拒）----

func TestThresholdsParseAndValidate(t *testing.T) {
	th, err := ParseThresholds("0.90,0.10,0.60,0.00,30")
	if err != nil || th != DefaultThresholds() {
		t.Fatalf("合法解析不符: %+v %v", th, err)
	}
	if _, err := ParseThresholds("0.9,0.1,0.6,0"); err == nil {
		t.Error("段数不符应拒绝")
	}
	if _, err := ParseThresholds("0.9,0.1,0.6,0,x"); err == nil {
		t.Error("非数值应拒绝")
	}
	if _, err := ParseThresholds("1.9,0.1,0.6,0,30"); err == nil {
		t.Error("比率越界（>1）应拒绝")
	}
	if _, err := ParseThresholds("0.9,0.1,0.6,0,0"); err == nil {
		t.Error("最小样本数 <1 应拒绝")
	}
	if _, err := ParseThresholds("-0.1,0.1,0.6,0,30"); err == nil {
		t.Error("负阈值应拒绝")
	}
}
