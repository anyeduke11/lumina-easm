// httpapi/confirm.go — 单用户高危动作确认端点（FR-LGR-005/CR-001/AX-5）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
)

func (s *Server) handleCreateConfirmation(w http.ResponseWriter, r *http.Request) {
	if s.confirm == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "confirmation_unavailable", "确认服务未启用")
		return
	}
	var in map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if !s.requirePasskeyStepUp(w, r, in["method"]) {
		return
	}
	c, err := s.confirm.Create(r.Context(), principalOf(r), requestIDOf(r), confirm.Confirmation{
		EntityID: in["entity_id"], Action: in["action"], Resource: in["resource"],
		Method: in["method"], Reason: in["reason"], ScopeHash: in["scope_hash"],
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleGetConfirmation(w http.ResponseWriter, r *http.Request) {
	if s.confirm == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "confirmation_unavailable", "确认服务未启用")
		return
	}
	c, err := s.confirm.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// requireConfirmation 在 EASM_REQUIRE_CONFIRMATION 开启（默认）时强制危险动作携带一次性确认。
// 闸开启但确认服务未装配=fail loud（501），不得静默放行（AX-5）。
func (s *Server) requireConfirmation(w http.ResponseWriter, r *http.Request, entityID, action, resource string) bool {
	if !s.confirmRequired {
		return true
	}
	if s.confirm == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "confirmation_unavailable",
			"确认服务未装配（EASM_REQUIRE_CONFIRMATION 已开启，拒绝降级放行）")
		return false
	}
	id := strings.TrimSpace(r.Header.Get("X-EASM-Confirmation"))
	if id == "" {
		writeError(w, requestIDOf(r), http.StatusForbidden, "confirmation_required",
			"高危动作需要 X-EASM-Confirmation（先 POST /v1/confirmations）")
		return false
	}
	if err := s.confirm.Consume(r.Context(), principalOf(r), requestIDOf(r), id, entityID, action); err != nil {
		failFrom(w, r, err)
		return false
	}
	return true
}
