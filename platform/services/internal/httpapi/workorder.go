// httpapi/workorder.go — 平台处置工单端点（WP-M2-03 / FR-CHN-004）：
// POST   /v1/tenants/{id}/workorders                  建单（投诉/删除申请）
// GET    /v1/tenants/{id}/workorders[?status=五态]     跟踪列表（催办台）
// GET    /v1/tenants/{id}/workorders/{wid}            单详情（含留痕）
// POST   /v1/tenants/{id}/workorders/{wid}/advance    状态转移 {to,operator,note}
// 状态机/关联台账/租户闸均在 workorder 服务内前置；端点只做权限、解析与错误映射。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

func (s *Server) handleCreateWorkOrder(w http.ResponseWriter, r *http.Request) {
	if s.wos == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "workorder_unavailable", "处置工单未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	var in workorder.WorkOrder
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	in.Tenant = r.PathValue("id") // 租户由路径绑定（body 伪装无效）
	if err := s.wos.Create(r.Context(), p, requestIDOf(r), &in); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) handleListWorkOrders(w http.ResponseWriter, r *http.Request) {
	if s.wos == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "workorder_unavailable", "处置工单未启用")
		return
	}
	tenantID := r.PathValue("id")
	st := r.URL.Query().Get("status")
	if st != "" {
		if !workorder.ValidStatus(st) {
			writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "status 须为五态之一（待整改/处置中/已通报平台/已下架/已处置）")
			return
		}
	}
	list, err := s.wos.List(r.Context(), principalOf(r), requestIDOf(r), tenantID, st)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

func (s *Server) handleGetWorkOrder(w http.ResponseWriter, r *http.Request) {
	if s.wos == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "workorder_unavailable", "处置工单未启用")
		return
	}
	got, err := s.wos.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("wid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, got)
}

func (s *Server) handleAdvanceWorkOrder(w http.ResponseWriter, r *http.Request) {
	if s.wos == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "workorder_unavailable", "处置工单未启用")
		return
	}
	var in struct {
		To       string `json:"to"`
		Operator string `json:"operator"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.To == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "to 必填（目标状态）")
		return
	}
	if err := s.wos.Advance(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("wid"), in.To, in.Operator, in.Note); err != nil {
		failFrom(w, r, err)
		return
	}
	got, err := s.wos.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("wid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, got)
}
