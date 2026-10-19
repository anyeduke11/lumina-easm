package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（FR-LGR-007/CR-002/A-08/FR-LGR-008 的对外可观测面）：通报必须经 REST 端到端成立——
// 生成真实单号与三要素、材料可导出且哈希对得上、回执无凭证即拒、重复回填锁定、
// ledger.notify 不再伪造占位单号、合规总结三段齐备带哈希。
func newNoticeServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	led := ledger.NewService(ledger.NewMemStore(), l)
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nn := notice.NewService(notice.NewMemStore(), l, led)
	nn.WithLedgerList(led)
	nn.WithEvidence(ev)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ops":   {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tsvc, asset.NewService(asset.NewMemStore(), l), tokens,
		WithLedger(led), WithNotice(nn)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

const noticeLedger = `{"id":"L-n1","phase":"P4","cat":"业务经营类","asset":"leak.onion","title":"客户库在暗市兜售","lv":"严重","src":"DRK-1/dark.web","date":"2026-10-17T00:00:00Z","action":"联系平台依法依规清理","owner":"安全运营","due":"2026-10-18T00:00:00Z"}`

func TestNoticeEndpoints(t *testing.T) {
	srv := newNoticeServer(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-n","name":"通报公司","short":"通报","root_domains":["n.cn"]}`)
	if r, _ := post(t, srv.URL, "/v1/tenants/t-n/ledger", "tok-admin", noticeLedger); r.StatusCode != http.StatusCreated {
		t.Fatal("台账建立失败")
	}

	// 非法目标 → 400
	if r, _ := post(t, srv.URL, "/v1/tenants/t-n/notices", "tok-admin", `{"ledger_id":"L-n1","target":"某媒体"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("非法目标期望 400，实际 %d", r.StatusCode)
	}
	// 幽灵台账 → 404（不得以不存在的事向监管报）
	if r, _ := post(t, srv.URL, "/v1/tenants/t-n/notices", "tok-admin", `{"ledger_id":"L-GHOST","target":"属地公安机关"}`); r.StatusCode != http.StatusNotFound {
		t.Errorf("幽灵台账期望 404，实际 %d", r.StatusCode)
	}

	// 生成通报：真实单号 + 三要素 + 证据 ref
	resp, body := post(t, srv.URL, "/v1/tenants/t-n/notices", "tok-admin", `{"ledger_id":"L-n1","target":"属地公安机关"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("建通报期望 201，实际 %d %s", resp.StatusCode, body)
	}
	for _, k := range []string{`"id":"NB-`, "material_hash", "created_at", "material_ref", `"deadline_h":24`} {
		if !strings.Contains(body, k) {
			t.Errorf("通报响应缺 %s: %s", k, body)
		}
	}
	nid := extractJSONField(body, "id")

	// 材料导出（text/markdown，含条目事实）
	req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/t-n/notices/"+nid+"/material", nil)
	req.Header.Set("Authorization", "Bearer tok-admin")
	mr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Body.Close()
	mb := readAll(mr)
	if mr.StatusCode != http.StatusOK || !strings.Contains(mb, "客户库在暗市兜售") || !strings.Contains(mb, nid) {
		t.Errorf("材料应含单号与条目事实: %d %s", mr.StatusCode, first(mb, 200))
	}

	// 回执：无凭证 400；有效 200 置已报送；重复回填 422 锁定
	if r, _ := post(t, srv.URL, "/v1/tenants/t-n/notices/"+nid+"/receipt", "tok-admin", `{}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("无回执号期望 400，实际 %d", r.StatusCode)
	}
	r2, b2 := post(t, srv.URL, "/v1/tenants/t-n/notices/"+nid+"/receipt", "tok-admin", `{"receipt_no":"公网文〔2026〕7号"}`)
	if r2.StatusCode != http.StatusOK || !strings.Contains(b2, "已报送") {
		t.Errorf("回执期望 200+已报送: %d %s", r2.StatusCode, b2)
	}
	if r, b := post(t, srv.URL, "/v1/tenants/t-n/notices/"+nid+"/receipt", "tok-admin", `{"receipt_no":"重复"}`); r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(b, "notice_locked") {
		t.Errorf("重复回执期望 422 notice_locked，实际 %d %s", r.StatusCode, b)
	}

	// 越权主体不得读他方材料（403/404 均为拒绝）
	req2, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/t-n/notices/"+nid+"/material", nil)
	req2.Header.Set("Authorization", "Bearer tok-ops") // 只见 t-a
	mr2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	mr2.Body.Close()
	if mr2.StatusCode == http.StatusOK {
		t.Error("越权主体不得读通报材料")
	}

	// 证据链交付包：JSON 逐项含 sha256/后端；?format=md 出附卷文本；越权主体不可导出
	rc, cb := get2(srv.URL+"/v1/tenants/t-n/notices/"+nid+"/chain", "tok-admin")
	if rc.StatusCode != http.StatusOK || !strings.Contains(cb, "sha256") || !strings.Contains(cb, "content_hash") {
		t.Errorf("证据链导出应含逐项哈希与整链哈希: %d %s", rc.StatusCode, first(cb, 240))
	}
	if !strings.Contains(cb, `"unresolved":0`) {
		t.Errorf("本用例证据链应全可核验（unresolved=0）: %s", first(cb, 300))
	}
	rq, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/t-n/notices/"+nid+"/chain?format=md", nil)
	rq.Header.Set("Authorization", "Bearer tok-admin")
	rresp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	mdBody := readAll(rresp)
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK || !strings.Contains(mdBody, "证据链") || !strings.Contains(mdBody, nid) {
		t.Errorf("md 导出应含交付包标题与单号: %d", rresp.StatusCode)
	}
	if r, _ := get2(srv.URL+"/v1/tenants/t-n/notices/"+nid+"/chain", "tok-ops"); r.StatusCode != http.StatusForbidden {
		t.Errorf("越权主体导出证据链期望 403，实际 %d", r.StatusCode)
	}

	// 催办面 + 合规总结
	_, ov := get2(srv.URL+"/v1/tenants/t-n/notices/overdue", "tok-admin")
	if !strings.Contains(ov, `"total":0`) {
		t.Errorf("已报送后超时清单应空: %s", ov)
	}
	rs, sum := get2(srv.URL+"/v1/tenants/t-n/report:summary", "tok-admin")
	if rs.StatusCode != http.StatusOK {
		t.Fatalf("总结期望 200，实际 %d", rs.StatusCode)
	}
	for _, sec := range []string{"排查发现突出问题", "整改措施及成效", "长效机制建设情况", "content_hash"} {
		if !strings.Contains(sum, sec) {
			t.Errorf("总结缺 %s: %s", sec, first(sum, 200))
		}
	}

	// ledger.notify 实接：返回真实 NB- 单号且 notice_persisted=true（不再伪造 N-*）
	rn, bn := post(t, srv.URL, "/v1/ledger/L-n1/notify", "tok-admin", `{}`)
	if rn.StatusCode != http.StatusOK || !strings.Contains(bn, "NB-") || !strings.Contains(bn, `"notice_persisted":true`) {
		t.Errorf("ledger notify 应生成真实通报单: %d %s", rn.StatusCode, first(bn, 220))
	}
	// 只读角色不得发起通报
	if r, _ := post(t, srv.URL, "/v1/tenants/t-n/notices", "tok-ro", `{"ledger_id":"L-n1","target":"属地公安机关"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("只读角色建通报期望 403，实际 %d", r.StatusCode)
	}
}

func readAll(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// first 截断辅助（失败信息只回显前 n 字节）。
func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
