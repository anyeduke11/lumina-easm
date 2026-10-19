package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// 批三端点回归：漏洞库动态优先级（导入→重算→详情匹配）、情报命中、归属三态+复核队列。
func TestKnowledgeEndpoints(t *testing.T) {
	srv := newM1Server(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-k","name":"知库公司","short":"知库","root_domains":["kbsec.cn"],"cidrs":["198.51.100.0/24"]}`)
	post(t, srv.URL, "/v1/tenants/t-k/assets", "tok-admin",
		`{"id":"ka-1","name":"cache.kbsec.cn","type":"web","risk":"high","exp":60,"owner":"运维部","found":"2026-10-17T00:00:00Z","status":"在用","beian":"已备案","source":"P2/Fofa","biz":"缓存","tags":["redis"]}`)
	// 列表：redis 条目重算后 matched_assets=1（影响面参与优先级=公式可复算的端点证明）
	_, body := get2(srv.URL+"/v1/vuln-library", "tok-admin")
	if !strings.Contains(body, "\"matched_assets\":1") {
		t.Errorf("redis 漏洞应 matched=1: %s", body[:min(200, len(body))])
	}
	// CSV 导入去重（A-04 端点面）
	_, imp := post(t, srv.URL, "/v1/vuln-library/import", "tok-admin", "cve,title,cvss,epss,severity,category,tags\nCVE-2026-77777,x,8,0.5,high,c,redis\nCVE-2026-77777,x,8,0.5,high,c,redis\n")
	if !strings.Contains(imp, `"inserted":1`) || !strings.Contains(imp, `"skipped":1`) {
		t.Errorf("导入去重错误: %s", imp)
	}
	// 情报命中
	post(t, srv.URL, "/v1/intel/import", "tok-admin", `[{"type":"domain","value":"c2.kbsec.cn","threat":"c2","confidence":0.9,"source":"test"}]`)
	_, hits := get2(srv.URL+"/v1/intel/hits", "tok-admin")
	if !strings.Contains(hits, "ka-1") {
		t.Errorf("情报应命中 ka-1: %s", hits)
	}
	// 归属三态：主域放行；疑似进队列且队列可查
	_, j1 := post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-k","domain":"oa.kbsec.cn","signals":{}}`)
	if !strings.Contains(j1, "\"verdict\":\"归属\"") || strings.Contains(j1, "\"queued_for_review\":true") {
		t.Errorf("主域应归属放行: %s", j1)
	}
	post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-k","domain":"weird.cn","signals":{"keyword_cooccur":3}}`)
	_, q := get2(srv.URL+"/v1/ownership/queue", "tok-admin")
	if !strings.Contains(q, "weird.cn") {
		t.Errorf("疑似应进复核队列: %s", q)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 为什么（M2-02 首小项「运行时消费」，与时间窗缺口同型处置）：FR-CHN-005 四类指纹不能只在
// 包内可算——必须经 REST 端到端可用：基线登记→judge 自动按租户取用→出归属；
// 且三道闸各自可验：越权主体登记=403（行级租户闸）、未登记基线携指纹=疑似进复核（不虚判归属）、
// 未登记租户读基线=404（不伪造空基线为「已登记」）。
func TestOwnershipFingerprintEndpoints(t *testing.T) {
	srv := newM1Server(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-fp","name":"指纹公司","short":"指纹","root_domains":["fp.cn"]}`)
	fpBody := `{"cert_fps":["AA:BB:CC:11:22"],"page_hashes":["9f2c4e7a"],"naming_rules":["hdws_","HDDC-"],"field_features":["cust_id_no","acct_bank_code","inner_emp_mail"]}`

	// ① 基线未登记：携证书指纹的暗网样本 → 疑似 + 进复核（不得虚判归属）
	_, j0 := post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-fp","domain":"leak.onion","signals":{"cert_fingerprint":"AA:BB:CC:11:22"}}`)
	if !strings.Contains(j0, "\"verdict\":\"疑似\"") || !strings.Contains(j0, "\"queued_for_review\":true") {
		t.Errorf("无基线时须疑似进复核: %s", j0)
	}
	// ② 越权主体（tok-tb 仅见 t-b）登记基线 → 403
	resp, _ := post(t, srv.URL, "/v1/tenants/t-fp/ownership/fingerprints", "tok-tb", fpBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("跨租户登记基线期望 403，实际 %d", resp.StatusCode)
	}
	// ③ 登记 → 201；读回含四类基线
	resp, got := post(t, srv.URL, "/v1/tenants/t-fp/ownership/fingerprints", "tok-admin", fpBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("登记期望 201，实际 %d %s", resp.StatusCode, got)
	}
	_, rd := get2(srv.URL+"/v1/tenants/t-fp/ownership/fingerprints", "tok-admin")
	for _, k := range []string{"cert_fps", "page_hashes", "naming_rules", "field_features"} {
		if !strings.Contains(rd, k) {
			t.Errorf("基线回读缺 %s: %s", k, rd)
		}
	}
	// ④ judge 自动取用基线：格式差异（小写+短横）仍命中证书指纹 → 归属放行
	_, j1 := post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-fp","domain":"leak.onion","signals":{"cert_fingerprint":"aa-bb-cc-11-22"}}`)
	if !strings.Contains(j1, "\"verdict\":\"归属\"") || strings.Contains(j1, "\"queued_for_review\":true") {
		t.Errorf("证书指纹命中基线应归属放行: %s", j1)
	}
	// ⑤ 数据字段特征 ≥3 命中 → 归属（端点面证明四类真被消费，非只证书一路）
	_, j2 := post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-fp","domain":"x.onion","signals":{"data_fields":["id","cust_id_no","acct_bank_code","inner_emp_mail"]}}`)
	if !strings.Contains(j2, "\"verdict\":\"归属\"") {
		t.Errorf("字段特征三命中应归属: %s", j2)
	}
	// ⑥ 未登记基线的租户读基线 → 404（不伪造「已登记」）
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-no","name":"无基线","short":"无","root_domains":["no.cn"]}`)
	resp, _ = get2(srv.URL+"/v1/tenants/t-no/ownership/fingerprints", "tok-admin")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("未登记基线期望 404，实际 %d", resp.StatusCode)
	}
}

// 越权主体不可读知识库匹配面（scopeAssets 按主体可见租户过滤）。
func TestKnowledgeScopeIsolation(t *testing.T) {
	srv := newM1Server(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-priv","name":"私","short":"私","root_domains":["priv.cn"]}`)
	post(t, srv.URL, "/v1/tenants/t-priv/assets", "tok-admin",
		`{"id":"pv-1","name":"redis.priv.cn","type":"web","risk":"low","exp":1,"owner":"o","found":"2026-10-17T00:00:00Z","status":"在用","beian":"未备案","source":"P2","biz":"b","tags":["redis"]}`)
	resp, _ := get2(srv.URL+"/v1/vuln-library", "tok-tb") // tok-tb 只见 t-b
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
}
