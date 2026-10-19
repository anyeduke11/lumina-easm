// httpapi/scan.go — 仓库凭据扫描端点（M2-01 首渠道 EXT-1）：
// POST /v1/tenants/{id}/scan:repo body {"dir":"/path","owner":"…"} → 采集管道。
// 授权闸（有效期+时间窗）在 collect 内部前置——403 no_valid_scope/not_in_time_window
// 直接透传（窗口承诺的对外可观测面）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func (s *Server) handleScanRepo(w http.ResponseWriter, r *http.Request) {
	if s.col == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "collect_unavailable", "采集管道未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in struct {
		Dir   string `json:"dir"`
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Dir == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "dir 必填（扫描目标目录）")
		return
	}
	res, err := s.col.ScanRepo(r.Context(), p, requestIDOf(r), r.PathValue("id"), in.Dir, in.Owner)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleScanPort 端口探测（M2-01 P3 主动渠道 SCAN-1）：授权闸（有效期+窗口）与
// rate_limit→nmap --max-rate 下发均在 collect 内——窗外/无授权 403 透传。
func (s *Server) handleScanPort(w http.ResponseWriter, r *http.Request) {
	if s.col == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "collect_unavailable", "采集管道未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in struct {
		Target string `json:"target"`
		Ports  string `json:"ports"`
		Owner  string `json:"owner"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Target == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "target 必填（探测目标）")
		return
	}
	res, err := s.col.ScanPort(r.Context(), p, requestIDOf(r), r.PathValue("id"), in.Target, in.Ports, in.Owner)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleScanDir 目录爆破（M2-01 P3 主动渠道 SCAN-2）。
func (s *Server) handleScanDir(w http.ResponseWriter, r *http.Request) {
	if s.col == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "collect_unavailable", "采集管道未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var in struct {
		URL   string `json:"url"`
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(body, &in); err != nil || !strings.HasPrefix(in.URL, "http") {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "url 必填且须为 http(s) 目标")
		return
	}
	res, err := s.col.ScanDir(r.Context(), p, requestIDOf(r), r.PathValue("id"), in.URL, in.Owner)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
