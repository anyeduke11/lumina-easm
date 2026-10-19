// Package scoring 攻击面四因子评分确定性核（M3-A / WP-M3-01 重基线）。
//
// 编号：FR-MIN-001/002 攻击面评分与定级、FR-GPH-004（M3-B 路径面依赖本包）、
// G8-01（四因子权重与等级阈值定稿=外部项，本包以配置注入承载）、AX-2 确定性、AX-3 可验证。
//
// 口径（设计方案 §3.1/§7；默认权重=登记口径，非定稿值）：
//   - 暴露可达 30 / 可利用性 30 / 资产重要性 25 / 凭据有效性 15（和=100，强制校验）；
//   - 每个因子归一到 0–100 的 raw，贡献=raw×权重/100，**总分=四因子贡献之和**（可逐步复算）；
//   - 等级阈值默认 80/60/40（严重/高/中/低），同样可配置注入。
//
// 输入全部来自确定性源（资产字段 + 台账条目聚合），无 AI 参与（AX-2）；
// **权重/阈值未定稿时必须显式标注来源**（默认=待 G8-01 定稿），不得伪装成已定稿口径。
package scoring

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DefaultWeightSource 默认权重口径来源标注（GAP-8 G8-01 未定稿）。
const DefaultWeightSource = "default（30/30/25/15；口径待 G8-01 定稿）"

// 因子码（稳定对外契约）。
const (
	CodeExposure            = "exposure"
	CodeExploitability      = "exploitability"
	CodeAssetValue          = "asset_value"
	CodeCredentialValidity  = "credential_validity"
	LabelExposure           = "暴露可达"
	LabelExploitability     = "可利用性"
	LabelAssetValue         = "资产重要性"
	LabelCredentialValidity = "凭据有效性"
)

// Weights 四因子权重（和必须=100，每项 ≥0）。
type Weights struct {
	Exposure           int `json:"exposure"`
	Exploitability     int `json:"exploitability"`
	AssetValue         int `json:"asset_value"`
	CredentialValidity int `json:"credential_validity"`
}

// Thresholds 等级阈值：score ≥ Severe=严重；≥ High=高；≥ Medium=中；其余=低。
type Thresholds struct {
	Severe int `json:"severe"`
	High   int `json:"high"`
	Medium int `json:"medium"`
}

// Inputs 评分输入（确定性：全部来自资产字段与台账聚合，无随机/时间项）。
type Inputs struct {
	PubliclyReachable bool   `json:"publicly_reachable"` // 公网可达（有公网 IP/域名在用）
	ExposureHits      int    `json:"exposure_hits"`      // 台账中 P1/P2 阶段命中数（搜索引擎/测绘可见）
	OpenSevereItems   int    `json:"open_severe_items"`  // 未闭环严重/高危台账条目
	ReproducedItems   int    `json:"reproduced_items"`   // 已复现验证条目（Verifs reproduced）
	AssetRisk         string `json:"asset_risk"`         // 资产风险等级：低/中/高/严重
	CredentialHits    int    `json:"credential_hits"`    // 未闭环凭证类（代码密码类）条目
	VerifiedCreds     int    `json:"verified_creds"`     // 已验证有效凭证
}

// Factor 因子明细（可解释：raw + 权重 + 贡献 + 依据）。
type Factor struct {
	Code         string  `json:"code"`
	Name         string  `json:"name"`
	Raw          float64 `json:"raw"`          // 归一 0–100
	Weight       int     `json:"weight"`       // 权重（四因子和=100）
	Contribution float64 `json:"contribution"` // raw×weight/100
	Basis        string  `json:"basis"`        // 依据（可解释，说明 raw 来自哪些输入）
}

// Result 评分结果（含明细与复算所需全部输入）。
type Result struct {
	AssetID      string     `json:"asset_id"`
	Tenant       string     `json:"tenant"`
	Score        float64    `json:"score"` // 0–100，=四因子贡献之和
	Level        string     `json:"level"` // 严重/高/中/低
	Factors      []Factor   `json:"factors"`
	Weights      Weights    `json:"weights"`
	Thresholds   Thresholds `json:"thresholds"`
	WeightSource string     `json:"weight_source"` // default（待 G8-01 定稿）/ env
	Formula      string     `json:"formula"`       // 可复算公式说明
	Inputs       Inputs     `json:"inputs"`        // 输入回显（复算面）
}

// DefaultWeights 登记口径默认权重（30/30/25/15）。
func DefaultWeights() Weights { return Weights{30, 30, 25, 15} }

// DefaultThresholds 默认等级阈值（80/60/40）。
func DefaultThresholds() Thresholds { return Thresholds{80, 60, 40} }

// Validate 权重校验：每项 ≥0 且和为 100（口径失真一律拒）。
func (w Weights) Validate() (Weights, error) {
	for _, v := range []int{w.Exposure, w.Exploitability, w.AssetValue, w.CredentialValidity} {
		if v < 0 {
			return w, fmt.Errorf("scoring: 权重不得为负: %+v", w)
		}
	}
	if s := w.Exposure + w.Exploitability + w.AssetValue + w.CredentialValidity; s != 100 {
		return w, fmt.Errorf("scoring: 四因子权重和须=100，实际 %d（%+v）", s, w)
	}
	return w, nil
}

// Validate 阈值校验：100 > Severe > High > Medium ≥ 0（单调）。
func (t Thresholds) Validate() (Thresholds, error) {
	if t.Severe <= t.High || t.High <= t.Medium || t.Medium < 0 || t.Severe >= 100 {
		return t, fmt.Errorf("scoring: 阈值须满足 100>严重>高>中≥0，实际 %+v", t)
	}
	return t, nil
}

// ParseWeights 解析 "30,30,25,15"（配置注入面；G8-01 定稿后换值即可）。
func ParseWeights(s string) (Weights, error) {
	p := strings.Split(strings.TrimSpace(s), ",")
	if len(p) != 4 {
		return Weights{}, fmt.Errorf("scoring: 权重须为 4 段（暴露,可利用,重要性,凭据），得 %q", s)
	}
	n := make([]int, 4)
	for i, v := range p {
		x, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return Weights{}, fmt.Errorf("scoring: 权重段 %d 非整数: %q", i, v)
		}
		n[i] = x
	}
	w := Weights{n[0], n[1], n[2], n[3]}
	return w.Validate()
}

// ParseThresholds 解析 "80,60,40"。
func ParseThresholds(s string) (Thresholds, error) {
	p := strings.Split(strings.TrimSpace(s), ",")
	if len(p) != 3 {
		return Thresholds{}, fmt.Errorf("scoring: 阈值须为 3 段（严重,高,中），得 %q", s)
	}
	n := make([]int, 3)
	for i, v := range p {
		x, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return Thresholds{}, fmt.Errorf("scoring: 阈值段 %d 非整数: %q", i, v)
		}
		n[i] = x
	}
	t := Thresholds{n[0], n[1], n[2]}
	return t.Validate()
}

// riskRaw 资产重要性归一（登记口径：低 25 / 中 50 / 高 75 / 严重 100；未知=中档 50 并注明）。
func riskRaw(risk string) (float64, string) {
	switch strings.TrimSpace(risk) {
	case "低", "low":
		return 25, "资产风险=低 → 25"
	case "中", "medium":
		return 50, "资产风险=中 → 50"
	case "高", "high":
		return 75, "资产风险=高 → 75"
	case "严重", "critical":
		return 100, "资产风险=严重 → 100"
	default:
		return 50, fmt.Sprintf("资产风险=%q 未识别 → 取中档 50（口径待 G8-01 定稿）", risk)
	}
}

// Compute 四因子评分（确定性）。raw 归一与依据：
//   - 暴露可达：公网可达 40 + P1/P2 命中 15/条（上限 100）
//   - 可利用性：未闭环严重/高危 20/条 + 已复现 30/条（上限 100）
//   - 资产重要性：风险等级映射
//   - 凭据有效性：未闭环凭证类 25/条 + 已验证有效 50/条（上限 100）
func Compute(tenant, assetID string, in Inputs, w Weights, th Thresholds) (Result, error) {
	if _, err := w.Validate(); err != nil {
		return Result{}, err
	}
	if _, err := th.Validate(); err != nil {
		return Result{}, err
	}
	neg := func(v int) int {
		if v < 0 {
			return 0
		}
		return v
	}
	ExposureHits, OpenSevere, Reproduced := neg(in.ExposureHits), neg(in.OpenSevereItems), neg(in.ReproducedItems)
	CredentialHits, VerifiedCreds := neg(in.CredentialHits), neg(in.VerifiedCreds)

	exp := 0.0
	if in.PubliclyReachable {
		exp += 40
	}
	exp = math.Min(100, exp+float64(ExposureHits)*15)
	expBasis := fmt.Sprintf("公网可达=%v(40) + P1/P2 命中 %d×15（上限 100）", in.PubliclyReachable, ExposureHits)

	expl := math.Min(100, float64(OpenSevere)*20+float64(Reproduced)*30)
	explBasis := fmt.Sprintf("未闭环严重/高危 %d×20 + 已复现 %d×30（上限 100）", OpenSevere, Reproduced)

	val, valBasis := riskRaw(in.AssetRisk)

	cred := math.Min(100, float64(CredentialHits)*25+float64(VerifiedCreds)*50)
	credBasis := fmt.Sprintf("未闭环凭证类 %d×25 + 已验证有效 %d×50（上限 100）", CredentialHits, VerifiedCreds)

	fs := []Factor{
		factor(CodeExposure, LabelExposure, exp, w.Exposure, expBasis),
		factor(CodeExploitability, LabelExploitability, expl, w.Exploitability, explBasis),
		factor(CodeAssetValue, LabelAssetValue, val, w.AssetValue, valBasis),
		factor(CodeCredentialValidity, LabelCredentialValidity, cred, w.CredentialValidity, credBasis),
	}
	score := 0.0
	for _, f := range fs {
		score += f.Contribution
	}
	score = math.Round(score*100) / 100 // 2 位小数（确定性，避免浮点噪声）
	return Result{
		AssetID: assetID, Tenant: tenant, Score: score, Level: levelOf(score, th), Factors: fs,
		Weights: w, Thresholds: th, WeightSource: DefaultWeightSource, Inputs: in,
		Formula: "score = Σ(因子 raw × 权重)/100，四因子权重和=100；明细见 factors（贡献之和=score）",
	}, nil
}

func factor(code, name string, raw float64, weight int, basis string) Factor {
	return Factor{Code: code, Name: name, Raw: raw, Weight: weight,
		Contribution: math.Round(raw*float64(weight)/100*100) / 100, Basis: basis}
}

// levelOf 等级判定（阈值可配置注入）。
func levelOf(score float64, th Thresholds) string {
	switch {
	case score >= float64(th.Severe):
		return "严重"
	case score >= float64(th.High):
		return "高"
	case score >= float64(th.Medium):
		return "中"
	default:
		return "低"
	}
}

// Recompute 复算面：由明细独立重算总分（与 Compute 结果必须一致=可验证）。
func Recompute(r Result) float64 {
	s := 0.0
	for _, f := range r.Factors {
		s += f.Contribution
	}
	return math.Round(s*100) / 100
}
