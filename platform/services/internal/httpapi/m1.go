// M1 REST 端点：语法库（IR-05）/ auth_scope 授权（CR-005）/ 插件注册表（IR-07）。
package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/plugin"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/syntax"
)

// ---- 语法库（F5 / FR-SYN）----

func (s *Server) handleSyntaxList(w http.ResponseWriter, r *http.Request) {
	groups := syntax.FilterPhase(r.URL.Query().Get("phase"))
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "total": len(groups)})
}

func (s *Server) handleSyntaxRender(w http.ResponseWriter, r *http.Request) {
	var in syntax.RenderInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	items, err := syntax.Render(in)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// ---- 授权 scope（F17 / FR-DSC-013）----

func (s *Server) handleUpsertAuthz(w http.ResponseWriter, r *http.Request) {
	if s.authz == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "authz_unavailable", "授权模块未启用")
		return
	}
	tenantID := r.PathValue("id")
	var sc authz.Scope
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	sc.Tenant = tenantID
	if sc.ValidFrom.IsZero() {
		sc.ValidFrom = time.Now().UTC()
	}
	if err := s.authz.Upsert(r.Context(), principalOf(r), requestIDOf(r), sc); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) handleGetAuthz(w http.ResponseWriter, r *http.Request) {
	if s.authz == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "authz_unavailable", "授权模块未启用")
		return
	}
	sc, ok, err := s.authz.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "该租户无授权记录")
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// handleAuthzCheck POST /v1/authz:check —— 扫描前目标校验（供编排/前端预检；拒绝已落审计）。
func (s *Server) handleAuthzCheck(w http.ResponseWriter, r *http.Request) {
	if s.authz == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "authz_unavailable", "授权模块未启用")
		return
	}
	var in struct {
		Tenant string `json:"tenant_id"`
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Tenant == "" || in.Target == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "tenant_id 与 target 必填")
		return
	}
	err := s.authz.CheckTarget(r.Context(), principalOf(r), requestIDOf(r), in.Tenant, in.Target, in.Port)
	if err != nil {
		code := "not_in_scope"
		switch err {
		case authz.ErrNoScope:
			code = "no_valid_scope"
		}
		writeError(w, requestIDOf(r), http.StatusForbidden, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": true, "target": in.Target})
}

// ---- 插件注册表（F18 / FR-PLG / IR-07）----

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "plugin_unavailable", "插件中心未启用")
		return
	}
	list := s.plugins.List(r.URL.Query().Get("cap"))
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

func (s *Server) handleRegisterPlugin(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "plugin_unavailable", "插件中心未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermManageTenants) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "仅平台管理员可注册插件（准入评审）")
		return
	}
	var c plugin.Contract
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if err := s.plugins.Register(r.Context(), c); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleUnregisterPlugin(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "plugin_unavailable", "插件中心未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermManageTenants) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "仅平台管理员可卸载插件")
		return
	}
	if err := s.plugins.Unregister(r.Context(), r.PathValue("id")); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unregistered"})
}
