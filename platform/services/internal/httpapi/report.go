// httpapi/report.go — 报告中心端点（WP-M2-09 / FR-RPT-001~004）。
// 租户作用域惯例：/v1/tenants/{id}/reports...（路径 {id} 为权威租户，忽略 body.tenant）。
// 导出面：md/json/pdf 三格式（PDF=CJK 内嵌确定性渲染，字体缺失=501 诚实边界）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/wangdev88/easm-platform/platform/services/internal/report"
)

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if s.rpt == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "report_unavailable", "报告中心未启用")
		return
	}
	var in report.Params
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	in.Tenant = r.PathValue("id") // 路径为权威租户绑定（防 body 越权指定他人租户）
	rep, err := s.rpt.Generate(r.Context(), principalOf(r), requestIDOf(r), in)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, rep)
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	if s.rpt == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "report_unavailable", "报告中心未启用")
		return
	}
	list, err := s.rpt.List(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	if s.rpt == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "report_unavailable", "报告中心未启用")
		return
	}
	rep, err := s.rpt.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("rid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleExportReport 导出：?format=md 直出 text/markdown 正文；?format=pdf 直出
// 确定性 PDF（CJK 内嵌，字体缺失=501 pdf_font_unavailable 诚实边界）；默认/其他=JSON 全量（FR-RPT-004）。
func (s *Server) handleExportReport(w http.ResponseWriter, r *http.Request) {
	if s.rpt == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "report_unavailable", "报告中心未启用")
		return
	}
	rep, err := s.rpt.Get(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), r.PathValue("rid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	switch r.URL.Query().Get("format") {
	case "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, rep.Text)
		return
	case "pdf":
		font := report.FindCJKFont()
		if font == "" {
			font = os.Getenv("EASM_PDF_FONT")
		}
		pdf, err := report.RenderPDF(rep, font)
		if err != nil {
			writeError(w, requestIDOf(r), http.StatusNotImplemented, "pdf_font_unavailable", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pdf)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
