// httpapi/scoring.go — M3-A 攻击面四因子评分端点（FR-MIN-001/002，WP-M3-01 重基线）。
// 评分计算面在 internal/scoring（纯确定性、零存储）；本文件只做：输入装配（资产+台账聚合）
// → 计算 → 明细直出（含复算所需全部输入）。权重/阈值经 WithScoring 注入，默认标注「待 G8-01 定稿」。
package httpapi

import (
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/scoring"
)

// handleAssetScore GET /v1/tenants/{id}/assets/{aid}/score：资产攻击面评分与四因子明细。
// 输入全部来自确定性源（资产字段 + 台账聚合），无 AI 参与（AX-2）；明细含依据，贡献之和=总分。
func (s *Server) handleAssetScore(w http.ResponseWriter, r *http.Request) {
	if s.ledger == nil || s.assets == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "scoring_unavailable", "评分所需资产/台账服务未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tenantID, assetID := r.PathValue("id"), r.PathValue("aid")
	a, err := s.assets.GetByID(r.Context(), p, requestIDOf(r), assetID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if a.Tenant != "" && a.Tenant != tenantID {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "资产不存在（跨租户不泄露存在性）")
		return
	}
	items, err := s.ledger.List(r.Context(), p, requestIDOf(r), ledger.Filter{Tenant: tenantID})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	res, err := scoring.Compute(tenantID, assetID, deriveInputs(a, items), s.scoreW, s.scoreTh)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleScoringWeights GET /v1/tenants/{id}/scoring/weights：当前评分口径（权重/阈值/来源/公式）。
// 为什么：口径必须可被外部复核——默认权重是**登记值而非定稿值**（GAP-8 G8-01），来源显式标注。
func (s *Server) handleScoringWeights(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"weights":       s.scoreW,
		"thresholds":    s.scoreTh,
		"weight_source": scoring.DefaultWeightSource,
		"formula":       "score = Σ(因子 raw × 权重)/100（四因子权重和=100）；等级按 thresholds 判定",
		"factors": []string{scoring.CodeExposure, scoring.CodeExploitability,
			scoring.CodeAssetValue, scoring.CodeCredentialValidity},
	})
}

// deriveInputs 由资产与台账聚合评分输入（确定性；口径见 scoring.Compute 注释）。
func deriveInputs(a asset.Asset, items []ledger.Item) scoring.Inputs {
	var in scoring.Inputs
	in.PubliclyReachable = a.IP != "" && a.Status == "在用"
	in.AssetRisk = a.Risk
	for _, it := range items {
		if it.Asset != a.ID && it.Asset != a.Name {
			continue
		}
		if it.Phase == "P1" || it.Phase == "P2" {
			in.ExposureHits++
		}
		open := it.Status != ledger.StatusClosed
		if open && (it.Level == "严重" || it.Level == "高") {
			in.OpenSevereItems++
		}
		if open && it.Category == "代码密码类" {
			in.CredentialHits++
		}
		for _, v := range it.Verifs {
			if v.Result == ledger.ResultReproduced {
				in.ReproducedItems++
				if it.Category == "代码密码类" {
					in.VerifiedCreds++
				}
			}
		}
	}
	return in
}
