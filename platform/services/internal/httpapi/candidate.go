// httpapi/candidate.go — 候选摄取端点（WP-M1-05 契约 / M2 前置）：
// POST /v1/candidates:ingest 收 JSONL（工具适配层/采集器投喂），行级校验+租户闸，
// GET /v1/candidates/unsupported 复核队列（不静默丢弃=fail loud 的界面）。
package httpapi

import (
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// candidateMaxBytes 单次摄取上限（JSONL 批量；防御大 body，超限 413）。
const candidateMaxBytes = 8 << 20 // 8 MiB

func (s *Server) handleIngestCandidates(w http.ResponseWriter, r *http.Request) {
	if s.cands == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "candidate_unavailable", "候选摄取未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, candidateMaxBytes+1))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if len(body) > candidateMaxBytes {
		writeError(w, requestIDOf(r), http.StatusRequestEntityTooLarge, "payload_too_large", "单次摄取上限 8MiB")
		return
	}
	acc, uns, err := s.cands.Ingest(r.Context(), p, string(body))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": acc, "unsupported": uns})
}

func (s *Server) handleListUnsupported(w http.ResponseWriter, r *http.Request) {
	if s.cands == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "candidate_unavailable", "候选摄取未启用")
		return
	}
	// 行无租户字段（摄取前坏行）→ 无法行级过滤，按平台级复核面收口（仅管理域可读）。
	if !principalOf(r).Can(rbac.PermManageTenants) {
		s.denyAccess(w, r, "candidate.unsupported", "", "/v1/candidates/unsupported", "无管理域权限")
		return
	}
	q := s.cands.Unsupported()
	writeJSON(w, http.StatusOK, map[string]any{"items": q, "total": len(q)})
}

// V-9：GET /v1/tenants/{id}/candidates/accepted 摄取留痕（PG 模式跨重启可查）。
// 行级租户闸：跨租户 403（留痕含原始行=可能含敏感上下文，不得越权可见）。
// 注意本端点无 Service 层（候选服务不做 RBAC），故租户闸与错误映射直接落在 handler，
// 与其他域「闸在 Service 内」的模式不同——这是候选契约包的定位（纯归一化管线）。
func (s *Server) handleListAcceptedCandidates(w http.ResponseWriter, r *http.Request) {
	if s.cands == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "candidate_unavailable", "候选摄取未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tenantID := r.PathValue("id")
	if !p.InScope(tenantID) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "tenant_out_of_scope", "越权租户")
		return
	}
	rows := s.cands.Accepted(tenantID)
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows)})
}
