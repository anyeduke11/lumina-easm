package scoring

import (
	"math"
	"strings"
	"testing"
)

// 固定输入（手算可复核）：
// exposure: 公网可达 40 + P1/P2 命中 2×15 = 70
// exploitability: 未闭环严重 2×20 = 40
// asset_value: risk=高 → 75
// credential_validity: 未闭环凭证 1×25 + 已验证 1×50 = 75
// 默认权重 30/30/25/15 → 70*30/100 + 40*30/100 + 75*25/100 + 75*15/100 = 21+12+18.75+11.25 = 63
func in() Inputs {
	return Inputs{
		PubliclyReachable: true, ExposureHits: 2,
		OpenSevereItems: 2, ReproducedItems: 0,
		AssetRisk:      "高",
		CredentialHits: 1, VerifiedCreds: 1,
	}
}

// 为什么（FR-MIN-001 / 一票否决「四因子权重和 100% 可复算」）：评分必须可解释——
// 明细逐项给出 raw/权重/贡献/依据，且贡献之和=总分（复算面 Recompute 独立成立）。
func TestComputeDeterministicAndExplainable(t *testing.T) {
	r, err := Compute("t-a", "a-1", in(), DefaultWeights(), DefaultThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(r.Score-63.0) > 1e-9 {
		t.Errorf("总分不符手算 63: %v", r.Score)
	}
	if len(r.Factors) != 4 {
		t.Fatalf("四因子明细应 4 项: %d", len(r.Factors))
	}
	want := map[string]float64{"exposure": 70, "exploitability": 40, "asset_value": 75, "credential_validity": 75}
	for _, f := range r.Factors {
		if math.Abs(f.Raw-want[f.Code]) > 1e-9 {
			t.Errorf("因子 %s raw 不符: %v 期望 %v", f.Code, f.Raw, want[f.Code])
		}
		if f.Basis == "" {
			t.Errorf("因子 %s 缺依据说明（不可解释）", f.Code)
		}
		if math.Abs(f.Contribution-f.Raw*float64(f.Weight)/100) > 1e-9 {
			t.Errorf("因子 %s 贡献计算不符: %v", f.Code, f.Contribution)
		}
	}
	if got := Recompute(r); math.Abs(got-r.Score) > 1e-9 {
		t.Errorf("复算面不符: %v vs %v", got, r.Score)
	}
	if r.Level != "高" { // 63 ≥ 60（默认阈值 80/60/40）
		t.Errorf("等级不符: %q（63 应=高）", r.Level)
	}
	r2, _ := Compute("t-a", "a-1", in(), DefaultWeights(), DefaultThresholds())
	if r.Score != r2.Score || r.Level != r2.Level {
		t.Error("同输入两次计算必须一致（确定性）")
	}
}

func TestLevelBoundaries(t *testing.T) {
	th := DefaultThresholds() // 80/60/40
	cases := []struct {
		name string
		in   Inputs
		want string
	}{
		{"全零=低", Inputs{}, "低"},
		// 手算：暴露 70×30%=21 + 可利用 20×30%=6 + 重要性 50×25%=12.5 + 凭据 25×15%=3.75 = 43.25 → 中
		{"仅中值=中", Inputs{PubliclyReachable: true, ExposureHits: 2, OpenSevereItems: 1,
			AssetRisk: "中", CredentialHits: 1}, "中"},
		// 手算：暴露 70×30%=21 + 可利用 40×30%=12 + 重要性 100×25%=25 + 凭据 25×15%=3.75 = 61.75 → 高
		{"高值=高", Inputs{PubliclyReachable: true, ExposureHits: 2, OpenSevereItems: 2,
			AssetRisk: "严重", CredentialHits: 1}, "高"},
		{"拉满=严重", Inputs{PubliclyReachable: true, ExposureHits: 10, OpenSevereItems: 10,
			AssetRisk: "严重", CredentialHits: 4, VerifiedCreds: 2}, "严重"},
	}
	for _, c := range cases {
		r, err := Compute("t-a", "a-1", c.in, DefaultWeights(), th)
		if err != nil {
			t.Fatal(err)
		}
		if r.Level != c.want {
			t.Errorf("%s: 等级=%q 期望 %q（score=%v）", c.name, r.Level, c.want, r.Score)
		}
	}
}

// 为什么（口径闸）：权重和≠100=评分口径失真（多算/少算）——必须装载即拒（fail loud）。
func TestWeightsMustSumTo100(t *testing.T) {
	for _, w := range []Weights{
		{30, 30, 25, 14}, {30, 30, 30, 15}, {0, 0, 0, 0}, {30, 30, 25, -15},
	} {
		if _, err := w.Validate(); err == nil {
			t.Errorf("非法权重应拒绝: %+v", w)
		}
	}
	if _, err := DefaultWeights().Validate(); err != nil {
		t.Errorf("默认权重（30/30/25/15）应合法: %v", err)
	}
	if _, err := Compute("t-a", "a-1", in(), Weights{30, 30, 25, 20}, DefaultThresholds()); err == nil {
		t.Error("权重和≠100 时 Compute 必须报错")
	}
}

// 为什么：阈值须单调（严重>高>中）且可配置注入（G8-01 定稿即换配置）。
func TestThresholdsValidation(t *testing.T) {
	if _, err := (Thresholds{60, 80, 40}).Validate(); err == nil {
		t.Error("阈值非单调应拒绝")
	}
	if _, err := DefaultThresholds().Validate(); err != nil {
		t.Errorf("默认阈值应合法: %v", err)
	}
}

// 为什么（配置注入面）：G8-01 定稿后仅换配置——解析必须严格，错配即拒。
func TestParseWeightsAndThresholds(t *testing.T) {
	w, err := ParseWeights("35,25,25,15")
	if err != nil || w.Exposure != 35 {
		t.Errorf("权重解析失败: %+v %v", w, err)
	}
	if _, err := ParseWeights("35,25,25"); err == nil {
		t.Error("字段数不足应拒绝")
	}
	if _, err := ParseWeights("35,25,25,x"); err == nil {
		t.Error("非数字应拒绝")
	}
	th, err := ParseThresholds("85,65,45")
	if err != nil || th.Severe != 85 {
		t.Errorf("阈值解析失败: %+v %v", th, err)
	}
	if _, err := ParseThresholds("85,65"); err == nil {
		t.Error("阈值字段数不足应拒绝")
	}
}

// 为什么：权重口径来源必须显式标注（默认=待 G8-01 定稿，不得伪装成已定稿）。
func TestWeightSourceLabeled(t *testing.T) {
	if !strings.Contains(DefaultWeightSource, "G8-01") {
		t.Errorf("默认权重来源须标注待定稿: %q", DefaultWeightSource)
	}
}
