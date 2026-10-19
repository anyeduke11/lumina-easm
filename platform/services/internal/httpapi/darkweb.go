// httpapi/darkweb.go — 暗网兜底巡检端点（WP-M2-02 / FR-CHN-005~008）：
// POST /v1/tenants/{id}/darkweb:inspect body {"samples":[…]} → 归属判定→量级→链路→线索包固化。
// 闸序（写权限/租户作用域/授权总闸 Validate/行级租户闸）在 darkweb 内前置；
// 租户指纹基线（FR-CHN-005 首小项）经 ownership:judge 自动按 tenant_id 取用——缺失=样本全疑似、不出包。
package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// darkwebMaxBytes 单次巡检样本批量上限（防御大 body，含截图字节）。
const darkwebMaxBytes = 16 << 20 // 16 MiB

func (s *Server) handleDarkwebInspect(w http.ResponseWriter, r *http.Request) {
	if s.dark == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "darkweb_unavailable", "暗网巡检未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tenantID := r.PathValue("id")
	t, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tenantID) // 行级租户闸（越权 403/未知 404）
	if err != nil {
		failFrom(w, r, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, darkwebMaxBytes+1))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if len(body) > darkwebMaxBytes {
		writeError(w, requestIDOf(r), http.StatusRequestEntityTooLarge, "payload_too_large", "单次巡检上限 16MiB")
		return
	}
	var in struct {
		Samples []darkweb.Sample `json:"samples"`
	}
	if err := json.Unmarshal(body, &in); err != nil || len(in.Samples) == 0 {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "samples 必填（暗网样本集）")
		return
	}
	id := ownership.Identity{Tenant: t.ID, Org: t.Name, Short: t.Short, Domains: t.RootDomains, CIDRs: t.CIDRs}
	res, err := s.dark.Inspect(r.Context(), p, requestIDOf(r), tenantID, id, in.Samples)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleListLeadPackages 按租户列举线索包（010 落库后可检索面；读权限+行级租户闸）。
func (s *Server) handleListLeadPackages(w http.ResponseWriter, r *http.Request) {
	if s.dark == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "darkweb_unavailable", "暗网巡检未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tenantID := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tenantID); err != nil {
		failFrom(w, r, err)
		return
	}
	pkgs, err := s.dark.ListPackages(r.Context(), tenantID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": pkgs, "total": len(pkgs)})
}

// handleGetLeadPackage 取回整包（租户+包 ID 双条件——跨租户=404 不泄露存在性，AX-5 口径）。
func (s *Server) handleGetLeadPackage(w http.ResponseWriter, r *http.Request) {
	if s.dark == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "darkweb_unavailable", "暗网巡检未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tenantID := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tenantID); err != nil {
		failFrom(w, r, err)
		return
	}
	pkg, ok, err := s.dark.GetPackage(r.Context(), tenantID, r.PathValue("pid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "线索包不存在")
		return
	}
	writeJSON(w, http.StatusOK, pkg)
}

// handleExportLeadPackage 线索包导出（FR-CHN-007）：?format=md 直出确定性通报文本
// （X-Content-Sha256 供独立复核）；默认/其他=JSON 全量。跨租户=404 不泄露存在性（AX-5）。
func (s *Server) handleExportLeadPackage(w http.ResponseWriter, r *http.Request) {
	if s.dark == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "darkweb_unavailable", "暗网巡检未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tenantID := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tenantID); err != nil {
		failFrom(w, r, err)
		return
	}
	pkg, ok, err := s.dark.GetPackage(r.Context(), tenantID, r.PathValue("pid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "线索包不存在")
		return
	}
	if r.URL.Query().Get("format") == "md" {
		body := darkweb.RenderPackageMD(pkg)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("X-Content-Sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(body))))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
		return
	}
	writeJSON(w, http.StatusOK, pkg)
}
