// IR-05 排查任务端点（F2 /v1/sweeps；MVP 进程内异步执行，Temporal 属 ENH-01）。
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
)

func (s *Server) handleCreateSweep(w http.ResponseWriter, r *http.Request) {
	if s.sweeps == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "sweep_unavailable", "五阶段工作流未启用")
		return
	}
	var in struct {
		Tenant string   `json:"tenant_id"`
		Phases []string `json:"phases"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Tenant == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "tenant_id 必填")
		return
	}
	if s.dispatch != nil { // ENH-01 Temporal 模式：建行(running)→派发→202（GET /v1/sweeps/{id} 轮询进度）
		sw, err := s.sweeps.CreateDispatched(r.Context(), in.Tenant, in.Phases)
		if err != nil {
			failFrom(w, r, err)
			return
		}
		// 派发前授权预检（快速失败；worker 侧同闸二次强制——不靠自觉）
		if s.authz != nil {
			if err := s.authz.Validate(r.Context(), in.Tenant); err != nil {
				failFrom(w, r, err)
				return
			}
		}
		if err := s.dispatch.Dispatch(r.Context(), sw); err != nil {
			writeError(w, requestIDOf(r), http.StatusServiceUnavailable, "dispatch_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, sw)
		return
	}
	sw, err := s.sweeps.Execute(r.Context(), principalOf(r), requestIDOf(r), in.Tenant, in.Phases)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	// 回退形态：进程内同步执行（Temporal 未配置时 MVP 原语义，测试契约不变）。
	writeJSON(w, http.StatusCreated, sw)
}

func (s *Server) handleListSweeps(w http.ResponseWriter, r *http.Request) {
	if s.sweeps == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "sweep_unavailable", "五阶段工作流未启用")
		return
	}
	p := principalOf(r)
	tenant := r.URL.Query().Get("tenant_id")
	if tenant != "" && !p.InScope(tenant) {
		s.denyAccess(w, r, "sweep.list", tenant, "/v1/sweeps", "越权租户")
		return
	}
	list := s.sweeps.List(tenant)
	visible := make([]sweep.Sweep, 0, len(list))
	for _, sw := range list {
		if p.InScope(sw.Tenant) {
			visible = append(visible, sw)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible, "total": len(visible)})
}

func (s *Server) handleGetSweep(w http.ResponseWriter, r *http.Request) {
	if s.sweeps == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "sweep_unavailable", "五阶段工作流未启用")
		return
	}
	sw, ok := s.sweeps.Get(r.PathValue("id"))
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "排查任务不存在")
		return
	}
	if !principalOf(r).InScope(sw.Tenant) {
		s.denyAccess(w, r, "sweep.get", sw.Tenant, r.URL.Path, "越权租户")
		return
	}
	writeJSON(w, http.StatusOK, sw)
}

func (s *Server) handleSweepMatrix(w http.ResponseWriter, r *http.Request) {
	if s.sweeps == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "sweep_unavailable", "五阶段工作流未启用")
		return
	}
	// 矩阵的租户行 = 主体可见租户（Scope 即边界，FR-TEN-005）
	tenants, err := s.tenants.List(r.Context(), principalOf(r))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	ids := make([]string, 0, len(tenants))
	for _, t := range tenants {
		ids = append(ids, t.ID)
	}
	rows := s.sweeps.Matrix(ids)
	// 越权兜底：Matrix 内部用了平台主体读台账，这里再按主体过滤一次
	visible := make([]sweep.Row, 0, len(rows))
	for _, row := range rows {
		if principalOf(r).InScope(row.Tenant) {
			visible = append(visible, row)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": visible, "phases": sweep.PhaseIDs()})
}
