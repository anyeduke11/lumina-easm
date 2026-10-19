// httpapi/secret.go — M3-C 密钥有效性验证端点（FR-CHN-002 / WP-M3-05）。
// 计算面在 internal/secret（格式→上下文→外呼三档），本文件只做权限/租户闸与参数校验；
// 未装配=501 secret_unavailable（诚实边界：不把「未验证」当「已验证」返回）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
)

type secretEntryInput struct {
	Rule        string  `json:"rule"`
	Location    string  `json:"location"`
	Masked      string  `json:"masked,omitempty"`
	Snippet     string  `json:"snippet,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	SourceFP    string  `json:"source_fp,omitempty"`
	ProbeURL    string  `json:"probe_url,omitempty"`
	EvidenceRef string  `json:"evidence_ref,omitempty"`
}

// handleSecretVerify POST /v1/tenants/{id}/secret:verify
func (s *Server) handleSecretVerify(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil || !s.secrets.Ready() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "secret_unavailable",
			"密钥有效性验证未装配（图谱未就绪）")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		Entries []secretEntryInput `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if len(in.Entries) == 0 {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "entries 不可为空")
		return
	}
	entries := make([]secret.Entry, 0, len(in.Entries))
	for _, e := range in.Entries {
		entries = append(entries, secret.Entry{Rule: e.Rule, Location: e.Location, Masked: e.Masked,
			Snippet: e.Snippet, Entropy: e.Entropy, SourceFP: e.SourceFP,
			ProbeURL: e.ProbeURL, EvidenceRef: e.EvidenceRef})
	}
	vs, err := s.secrets.Verify(r.Context(), tid, entries)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	linked := 0
	for _, v := range vs {
		if v.Linked {
			linked++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "total": len(vs), "verdicts": vs, "linked": linked,
		"probe_enabled": s.secrets.ProbeEnabled(),
		"basis":         "格式→上下文→外呼三档；仅验证为可用的凭据连接攻击路径边（FR-CHN-002 仅上报可用凭据）",
	})
}

// handleSecretMetrics GET /v1/tenants/{id}/secret/metrics
func (s *Server) handleSecretMetrics(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil || !s.secrets.Ready() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "secret_unavailable",
			"密钥有效性验证未装配（图谱未就绪）")
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
	m, err := s.secrets.Metrics(r.Context(), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}
