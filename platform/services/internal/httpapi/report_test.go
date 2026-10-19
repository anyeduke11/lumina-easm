package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（FR-RPT-001~004 / A-05 的对外可观测面）：报告必须经 REST 端到端成立——
// 由所选租户实时事实生成（切租户全变）、参数非法即拒、历史可列可取、md 直出且正文含事实、
// 路径 {id} 为权威租户（body 越权指定无效）、越权主体 403、未装配报告中心时显式 501 而非静默空转。
func newReportServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	led := ledger.NewService(ledger.NewMemStore(), l)
	rpt := report.NewService(report.NewMemStore(), l, tsvc, led)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ops":   {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tsvc, asset.NewService(asset.NewMemStore(), l), tokens,
		WithLedger(led), WithReport(rpt)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

const reportLedger = `{"id":"L-r1","phase":"P4","cat":"代码密码类","asset":"github.com/t-r/repo","title":"报告中心实测泄露条目","lv":"严重","src":"GH/r1","date":"2026-10-17T00:00:00Z","action":"安全加固","owner":"安全运营","due":"2026-10-25T00:00:00Z"}`

func TestReportEndpoints(t *testing.T) {
	srv := newReportServer(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-r","name":"报告公司","short":"报告","root_domains":["r.cn"]}`)
	if r, b := post(t, srv.URL, "/v1/tenants/t-r/ledger", "tok-admin", reportLedger); r.StatusCode != http.StatusCreated {
		t.Fatalf("台账建立失败: %d %s", r.StatusCode, b)
	}

	// 生成：201 + 确定性单号/哈希/章节；正文必须由实时事实聚合（含台账标题）
	cr, cb := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"d7","audience":"exec"}`)
	if cr.StatusCode != http.StatusCreated {
		t.Fatalf("生成报告期望 201，实际 %d %s", cr.StatusCode, cb)
	}
	for _, k := range []string{`"id":"RPT-`, "content_hash", `"sections":[`, `"period":"d7"`, `"audience":"exec"`} {
		if !strings.Contains(cb, k) {
			t.Errorf("报告响应缺 %s: %s", k, first(cb, 240))
		}
	}
	rid := extractJSONField(cb, "id")
	if !strings.HasPrefix(rid, "RPT-") {
		t.Fatalf("报告单号期望 RPT- 前缀: %q", rid)
	}

	// 非法周期/受众 → 400（不得落库一份口径非法的报告）
	if r, b := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"year","audience":"exec"}`); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "invalid_request") {
		t.Errorf("非法周期期望 400 invalid_request，实际 %d %s", r.StatusCode, first(b, 160))
	}
	if r, _ := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"d7","audience":"auditor"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("非法受众期望 400，实际 %d", r.StatusCode)
	}
	// 未知租户 → 404（不得为幽灵客户凭空出报告）
	if r, _ := post(t, srv.URL, "/v1/tenants/t-ghost/reports", "tok-admin", `{"period":"d7","audience":"exec"}`); r.StatusCode != http.StatusNotFound {
		t.Errorf("未知租户期望 404，实际 %d", r.StatusCode)
	}

	// 历史：同参再生成（确定性幂等覆盖）后列表仅 1 条；选章节新增第 2 条
	if r, _ := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"d7","audience":"exec"}`); r.StatusCode != http.StatusCreated {
		t.Errorf("同参复生成期望 201，实际 %d", r.StatusCode)
	}
	if r, b := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"d30","audience":"compliance","sections":["kpi"]}`); r.StatusCode != http.StatusCreated || !strings.Contains(b, `"sections":["kpi"]`) {
		t.Errorf("章节选择期望 201 且仅 kpi，实际 %d %s", r.StatusCode, first(b, 200))
	}
	lr, lb := get2(srv.URL+"/v1/tenants/t-r/reports", "tok-admin")
	if lr.StatusCode != http.StatusOK || !strings.Contains(lb, `"total":2`) {
		t.Errorf("历史列表期望 201 总数 2，实际 %d %s", lr.StatusCode, first(lb, 200))
	}

	// 取单份
	gr, gb := get2(srv.URL+"/v1/tenants/t-r/reports/"+rid, "tok-admin")
	if gr.StatusCode != http.StatusOK || !strings.Contains(gb, `"id":"`+rid+`"`) {
		t.Errorf("取报告期望 200 且单号一致，实际 %d %s", gr.StatusCode, first(gb, 200))
	}

	// md 导出：Content-Type=text/markdown 且正文含实时事实（标题）
	req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/t-r/reports/"+rid+"/export?format=md", nil)
	req.Header.Set("Authorization", "Bearer tok-admin")
	mr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if ct := mr.Header.Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Errorf("md 导出 Content-Type 期望 text/markdown，实际 %q", ct)
	}
	mb := readAll(mr)
	mr.Body.Close()
	if mr.StatusCode != http.StatusOK || !strings.Contains(mb, "报告中心实测泄露条目") {
		t.Errorf("md 正文应含台账事实: %d %s", mr.StatusCode, first(mb, 200))
	}

	// 路径租户权威：body 即便伪造他人租户，也必须按 t-r 出数
	rr, rb := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"tenant":"t-a","period":"d7","audience":"exec"}`)
	if rr.StatusCode != http.StatusCreated || !strings.Contains(rb, `"tenant":"t-r"`) {
		t.Errorf("路径租户应为权威绑定，实际 %d %s", rr.StatusCode, first(rb, 200))
	}

	// 越权主体（仅 t-a 作用域）不得生成/读取 t-r 报告
	if r, _ := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-ops", `{"period":"d7","audience":"exec"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("越权生成期望 403，实际 %d", r.StatusCode)
	}
	if r, _ := get2(srv.URL+"/v1/tenants/t-r/reports/"+rid, "tok-ops"); r.StatusCode != http.StatusForbidden {
		t.Errorf("越权读取期望 403，实际 %d", r.StatusCode)
	}
}

// 未装配报告中心时必须显式 501（fail loud），而不是静默返回空集。
func TestReportUnavailableWhenNotWired(t *testing.T) {
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	tokens := map[string]rbac.Principal{"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}}
	srv := httptest.NewServer(New(tsvc, asset.NewService(asset.NewMemStore(), l), tokens).Handler())
	t.Cleanup(srv.Close)

	if r, b := post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-x","name":"X","short":"x","root_domains":["x.cn"]}`); r.StatusCode != http.StatusCreated {
		t.Fatalf("建租户失败: %d %s", r.StatusCode, b)
	}
	if r, b := get2(srv.URL+"/v1/tenants/t-x/reports", "tok-admin"); r.StatusCode != http.StatusNotImplemented || !strings.Contains(b, "report_unavailable") {
		t.Errorf("未装配期望 501 report_unavailable，实际 %d %s", r.StatusCode, first(b, 160))
	}
}

// 为什么（FR-RPT-004 PDF 遗留销账）：PDF 导出必须真实产出（结构合法 + CJK 内嵌），
// 且字体缺失时 501 诚实标注（不伪造交付物）；md/json 契约不因新增分支回归。
func TestReportExportPDF(t *testing.T) {
	srv := newReportServer(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-r","name":"报告公司","short":"报告","root_domains":["r.cn"]}`)
	post(t, srv.URL, "/v1/tenants/t-r/ledger", "tok-admin", reportLedger)
	_, cb := post(t, srv.URL, "/v1/tenants/t-r/reports", "tok-admin", `{"period":"d7","audience":"exec"}`)
	rid := extractJSONField(cb, "id")

	req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/t-r/reports/"+rid+"/export?format=pdf", nil)
	req.Header.Set("Authorization", "Bearer tok-admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(resp)
	if report.FindCJKFont() == "" && os.Getenv("EASM_PDF_FONT") == "" {
		// 无字体环境：501 pdf_font_unavailable=诚实能力边界（合法形态）
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("无字体环境期望 501，实际 %d", resp.StatusCode)
		}
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PDF 导出期望 200，实际 %d %s", resp.StatusCode, body[:min(200, len(body))])
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type 期望 application/pdf: %q", ct)
	}
	if !strings.HasPrefix(body, "%PDF-1.4") || !strings.Contains(body, "%%EOF") {
		t.Error("PDF 结构不完整（头/尾缺失）")
	}
	if !strings.Contains(body, "FontFile2") {
		t.Error("CJK 字体未内嵌（打开即乱码=伪造交付）")
	}
	// md/json 不回归
	resp2, body2 := get2(srv.URL+"/v1/tenants/t-r/reports/"+rid+"/export?format=md", "tok-admin")
	if resp2.StatusCode != http.StatusOK || !strings.Contains(body2, "高管") {
		t.Error("md 导出回归（应含摘要章节）")
	}
}
