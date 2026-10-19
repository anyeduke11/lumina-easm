// httpapi/evidence.go — 证据对象存储 REST 面（ENH-05）：POST 固化、GET 回溯。
// 语义（C-5）：任一结论可由 `raw_ref` 回溯到不可变原始产物。租户由 handler 绑定，
// key=<tenant>/<sha256(data)>.bin，同内容同租户=同 key→二次 PUT=409 ErrImmutable（WORM）。
package httpapi

import (
	"errors"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// evidenceMaxBytes=单次固化上限（防御性；大文件走 multipart/直传签名 URL 属后续增强）。
const evidenceMaxBytes = 20 << 20 // 20 MiB

func (s *Server) handlePutEvidence(w http.ResponseWriter, r *http.Request) {
	if s.evid == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "evidence_unavailable", "证据存储未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tid := r.URL.Query().Get("tenant")
	if tid == "" || !p.InScope(tid) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "tenant 缺失或越权")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, evidenceMaxBytes+1))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if len(body) == 0 {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "证据字节不可为空")
		return
	}
	sha := evidence.Hash(body)
	key := tid + "/" + sha + ".bin"
	ref, err := s.evid.Put(r.Context(), key, body)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ref": ref, "sha256": sha, "size": len(body), "backend": s.evid.Kind(),
	})
}

func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request) {
	if s.evid == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "evidence_unavailable", "证据存储未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	ref := r.URL.Query().Get("ref")
	tid := r.URL.Query().Get("tenant")
	if ref == "" || tid == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "ref 与 tenant 必填")
		return
	}
	if !p.InScope(tid) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "越权租户")
		return
	}
	// C-5 越权防线：ref 须属本租户（口径统一在 evidence.RefInTenant）。
	if !evidence.RefInTenant(ref, tid) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "ref_tenant_mismatch", "ref 与 tenant 不匹配")
		return
	}
	data, err := s.evid.Get(r.Context(), ref)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Evidence-Sha256", evidence.Hash(data))
	w.Header().Set("X-Evidence-Backend", s.evid.Kind())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// evStatus 把证据层错误映射为 HTTP 状态/错误码（与 mapErr 集成）。
func evStatus(err error) (int, string, bool) {
	switch {
	case errors.Is(err, evidence.ErrNotFound):
		return http.StatusNotFound, "not_found", true
	case errors.Is(err, evidence.ErrImmutable):
		return http.StatusConflict, "evidence_immutable", true
	case errors.Is(err, evidence.ErrEmpty), errors.Is(err, evidence.ErrBadKey), errors.Is(err, evidence.ErrBadRef):
		return http.StatusBadRequest, "invalid_request", true
	}
	return 0, "", false
}
