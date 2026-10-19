// httpapi/shadowit.go — M3-C 影子 IT 收敛建议与纳管人审面（FR-MIN-003 / WP-M3-04）。
// 建议面纯计算无副作用；纳管面必须过「判定=归属 + 人审人 + 动作=admit」双闸（红线落代码）。
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
)

type shadowInput struct {
	Domain      string            `json:"domain"`
	Signals     ownership.Signals `json:"signals"`
	EvidenceRef string            `json:"evidence_ref,omitempty"`
}

// handleShadowAdvise POST /v1/tenants/{id}/shadow:advise（只产出建议，不写任何东西）
func (s *Server) handleShadowAdvise(w http.ResponseWriter, r *http.Request) {
	if s.shadow == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "shadow_unavailable", "影子 IT 收敛建议未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tid := r.PathValue("id")
	t, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	var in shadowInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.Domain == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "domain 必填")
		return
	}
	adv, err := s.shadow.Advise(shadowit.Input{
		Tenant: tid, Domain: in.Domain, Signals: in.Signals, EvidenceRef: in.EvidenceRef,
		Identity: ownership.Identity{Tenant: t.ID, Org: t.Name, Short: t.Short,
			Domains: t.RootDomains, CIDRs: t.CIDRs},
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"advice": adv,
		"note":   "建议无副作用：不写资产、不写图谱；纳管须经 /shadow/admit 人审（FR-MIN-003 不自动入账）",
	})
}

// handleShadowAdmit POST /v1/tenants/{id}/shadow/admit（人审纳管：双闸通过后写资产）
func (s *Server) handleShadowAdmit(w http.ResponseWriter, r *http.Request) {
	if s.shadow == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "shadow_unavailable", "影子 IT 收敛建议未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tid := r.PathValue("id")
	t, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		shadowInput
		Action   string     `json:"action"`
		Reviewer string     `json:"reviewer"`
		Asset    assetInput `json:"asset"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	adv, err := s.shadow.Advise(shadowit.Input{
		Tenant: tid, Domain: in.Domain, Signals: in.Signals, EvidenceRef: in.EvidenceRef,
		Identity: ownership.Identity{Tenant: t.ID, Org: t.Name, Short: t.Short,
			Domains: t.RootDomains, CIDRs: t.CIDRs},
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	// 红线闸：判定非归属 / 缺人审人 / 非纳管动作 → 一律拒绝（不自动入账）
	if err := s.shadow.CheckAdmit(adv, in.Action, in.Reviewer); err != nil {
		switch {
		case errors.Is(err, shadowit.ErrNotOwned):
			writeError(w, requestIDOf(r), http.StatusConflict, "not_owned",
				"判定为"+adv.Verdict+"的资产不得纳管（须先人工复核归属）")
		default:
			writeError(w, requestIDOf(r), http.StatusBadRequest, "review_required",
				"纳管须人审：reviewer 必填且 action=admit")
		}
		return
	}
	a := asset.Asset{
		ID: in.Asset.ID, Tenant: tid, Name: in.Asset.Name, Type: in.Asset.Type,
		TypeLabel: in.Asset.TypeLabel, IP: in.Asset.IP, Risk: in.Asset.Risk, Exp: in.Asset.Exp,
		Owner: in.Asset.Owner, Status: in.Asset.Status, Beian: in.Asset.Beian,
		Source: in.Asset.Source, Biz: in.Asset.Biz, Tags: in.Asset.Tags,
		Ports: in.Asset.Ports, Tech: in.Asset.Tech,
	}
	if in.Asset.Found != "" {
		ts, err := time.Parse(time.RFC3339, in.Asset.Found)
		if err != nil {
			writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "found 必须为 ISO 8601/RFC3339")
			return
		}
		a.Found = ts
	}
	if a.Name == "" {
		a.Name = in.Domain
	}
	if a.Type == "" {
		a.Type = "domain"
	}
	if a.Source == "" {
		// 留痕：纳管来源必须可追溯到人审人与判定（谁纳的、凭什么纳的）
		a.Source = "M3-C 纳管/复核人:" + in.Reviewer + "/建议:" + adv.ID
	}
	created, err := s.assets.Create(r.Context(), p, requestIDOf(r), a)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"asset": toAssetView(created), "advice": adv,
		"reviewer": in.Reviewer, "admitted": true,
	})
}
