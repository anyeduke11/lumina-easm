package httpapi

// M4-07 / FR-HRN-10 计量与预算出口：GET usage/summary、POST usage/budget。
// 语义：summary=月度 token 汇总（byFeature/byModel=灰度观测面）+ 预算状态；
// budget=租户级月度预算设置（PermManageTenants；人在环口径变更可追溯）。

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// handleUsageSummary GET /v1/tenants/{id}/usage/summary?month=YYYY-MM
func (s *Server) handleUsageSummary(w http.ResponseWriter, r *http.Request) {
	if s.usageSvc == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "usage_unavailable", "计量面未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	sum, err := s.usageSvc.Summary(r.Context(), tid, r.URL.Query().Get("month"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": sum,
		"basis":   "FR-HRN-10：AI 面按租户 token 计量（feature=消费面、model=版本灰度观测）；超预算不阻断调用（硬闸=evalset 放量门禁），告警经 notify 统一出口（当月一次）",
	})
}

// handleUsageBudget POST /v1/tenants/{id}/usage/budget
func (s *Server) handleUsageBudget(w http.ResponseWriter, r *http.Request) {
	if s.usageSvc == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "usage_unavailable", "计量面未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermManageTenants) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "预算管理需租户管理权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		MonthlyTokens *int64 `json:"monthly_tokens"`
		By            string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if in.MonthlyTokens == nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "monthly_tokens 必填（0=清零预算=不再告警，如实）")
		return
	}
	if err := s.usageSvc.SetBudget(r.Context(), tid, *in.MonthlyTokens, in.By); err != nil {
		failFrom(w, r, err)
		return
	}
	b, ok, err := s.usageSvc.GetBudget(r.Context(), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "monthly_tokens": b, "budget_set": ok,
		"basis": "口径变更=新事实（当月告警标记清除，可重新告警）；0=清零（不再告警）",
	})
}
