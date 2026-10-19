// httpapi/notice.go — 线索通报与合规报送端点（WP-M2-04 / FR-LGR-007~008、FR-RPT-005、CR-002、A-08）。
// 过渡形态（G8-02 真实报送通道未触达）：系统生成通报单号+通用模板材料+三要素留痕，
// 「已报送」的唯一合法路径=人工投递后回执录入；合规总结=结构完整可导出（定稿格式待 G8-02）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func (s *Server) handleCreateNotice(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	var in struct {
		LedgerID string `json:"ledger_id"`
		Target   string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.LedgerID == "" || in.Target == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "ledger_id 与 target 必填")
		return
	}
	n, err := s.not.Create(r.Context(), p, requestIDOf(r), r.PathValue("id"), in.LedgerID, in.Target)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) handleListNotices(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	st := r.URL.Query().Get("status")
	if st != "" && st != notice.StatusPending && st != notice.StatusSubmitted {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "status 须为 待报送|已报送")
		return
	}
	list, err := s.not.List(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), st)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// handleOverdueNotices A-08 催办面：超时未报送清单（每项带 overdue 显著标识）。
func (s *Server) handleOverdueNotices(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	list, err := s.not.Overdue(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "total": len(list),
		"deadline_h": map[string]int{notice.TargetPolice: 24, notice.TargetCenter: 48}})
}

// handleNoticeMaterial 导出通报材料（text/markdown；行级租户闸；固化面可回溯）。
func (s *Server) handleNoticeMaterial(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	text, err := s.not.Material(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("nid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, text)
}

func (s *Server) handleNoticeReceipt(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	var in struct {
		ReceiptNo   string `json:"receipt_no"`
		SubmittedAt string `json:"submitted_at"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || strings.TrimSpace(in.ReceiptNo) == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "receipt_no 必填（无凭证不得置已报送）")
		return
	}
	at := time.Time{}
	if in.SubmittedAt != "" {
		t, err := time.Parse(time.RFC3339, in.SubmittedAt)
		if err != nil {
			writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "submitted_at 须为 RFC3339")
			return
		}
		at = t
	}
	if err := s.not.MarkReceipt(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("nid"), in.ReceiptNo, at); err != nil {
		failFrom(w, r, err)
		return
	}
	n, err := s.not.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("nid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

// handleNoticeChain 导出通报证据链交付包：默认 JSON（含逐项 sha256/字节/后端与 unresolved
// 原因），`?format=md` 出可直接附卷的 Markdown 文本（读权限+行级租户闸；C-5 复核口径）。
func (s *Server) handleNoticeChain(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	ch, err := s.not.Chain(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("nid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ch.Text)
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// handleSummaryReport 合规报送总结导出（FR-LGR-008/FR-RPT-005：三段结构+内容哈希）。
func (s *Server) handleSummaryReport(w http.ResponseWriter, r *http.Request) {
	if s.not == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notice_unavailable", "线索通报未启用")
		return
	}
	rep, err := s.not.Summary(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
