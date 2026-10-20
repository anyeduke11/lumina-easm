package httpapi

// M3-D 多模态判敏出口（WP-M3-03 / FR-CLS-006 / AIL-5/6 / ENH-03）。
// ENH-03 未装配=501 mm_unavailable（诚实边界，不静默降级）。

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/mm"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// handleMmAnalyze POST /v1/tenants/{id}/mm:analyze
// 单点、人在环的多模态判敏：AI 结论=ai_assisted 参考（不入台账）；资产在图内则富化
// mm_* 可解释 props（AIL-5/6），不在图内 graphed=false（不伪造落点）。
func (s *Server) handleMmAnalyze(w http.ResponseWriter, r *http.Request) {
	if s.mm == nil || !s.mm.Ready() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "mm_unavailable",
			"多模态判敏未装配（ENH-03 AI 面未配置：EASM_AI_API_KEY/BASE_URL/MODEL 三件套）")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限（AI 分析会外呼并可能富化图谱）")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		AssetFP     string `json:"asset_fp,omitempty"`
		ImageURL    string `json:"image_url"`
		Question    string `json:"question,omitempty"`
		EvidenceRef string `json:"evidence_ref,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	res, err := s.mm.Analyze(r.Context(), mm.Input{
		Tenant: tid, AssetFP: in.AssetFP, ImageURL: in.ImageURL,
		Question: in.Question, EvidenceRef: in.EvidenceRef,
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": res,
		"basis":  "AI 结论=ai_assisted 参考（AX-2：不入台账，处置仍走确定性三重门+人审）；资产在图内已富化 mm_* 可解释 props（AIL-5/6）",
	})
}
