package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// 批四端点回归：监控器创建/权限、导入事件→告警（FR-MON-001/003 近似）、
// 手动 run+去重（FR-MON-004）、复核队列人工出口（PRD R2 可审计出口）。
func TestMonitorEndpoints(t *testing.T) {
	srv := newM1Server(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-m","name":"监测公司","short":"监测","root_domains":["kbmon.cn"]}`)
	post(t, srv.URL, "/v1/tenants/t-m/assets", "tok-admin",
		`{"id":"ma-1","name":"redis.kbmon.cn","type":"web","risk":"high","exp":70,"owner":"运维","found":"2026-10-17T00:00:00Z","status":"在用","beian":"已备案","source":"P2","biz":"缓存","tags":["redis"]}`)

	// 创建监控器（周期任务=平台配置写，仅 ManageTenants）
	resp, body := post(t, srv.URL, "/v1/monitors", "tok-admin", `{"name":"15min","kind":"both","interval_sec":900}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"id":1`) {
		t.Fatalf("创建监控器失败: %d %s", resp.StatusCode, body)
	}
	if resp, _ = post(t, srv.URL, "/v1/monitors", "tok-tb", `{"name":"x","kind":"vuln","interval_sec":60}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("R1 不得创建定时监控: %d", resp.StatusCode)
	}
	if resp, _ = post(t, srv.URL, "/v1/monitors", "tok-admin", `{"name":"x","kind":"wifi","interval_sec":60}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 kind 应 400: %d", resp.StatusCode)
	}

	// 事件驱动：高危 CVE 导入即触发匹配 → 告警立现（无需等周期）
	post(t, srv.URL, "/v1/vuln-library/import", "tok-admin", "cve,title,cvss,epss,severity,category,tags\nCVE-2026-88001,新redis洞,9.5,0.9,critical,cache,redis\n")
	_, al := get2(srv.URL+"/v1/alerts", "tok-admin")
	if !strings.Contains(al, "vuln_match|CVE-2026-88001|ma-1") {
		t.Errorf("导入事件应即时产出告警: %s", al)
	}
	if strings.Contains(al, "\"severity\":\"medium\"") {
		t.Error("告警流混入 medium（只推高危违例）")
	}

	// 手动 run（stub provider 无可见资产）→ 去重：new=0 且总量不变
	_, r1 := post(t, srv.URL, "/v1/monitors/1/run", "tok-admin", ``)
	if !strings.Contains(r1, `"new":0`) {
		t.Errorf("重扫不得复制告警: %s", r1)
	}
	_, al2 := get2(srv.URL+"/v1/alerts", "tok-admin")
	n1 := strings.Count(al, "\"key\"")
	n2 := strings.Count(al2, "\"key\"")
	if n1 != n2 {
		t.Errorf("run 前后告警数应一致: %d vs %d", n1, n2)
	}

	// 情报导入事件：命中资产的 IOC → intel_hit 告警，置信度排序首条
	post(t, srv.URL, "/v1/intel/import", "tok-admin", `[{"type":"domain","value":"redis.kbmon.cn","threat":"phishing","confidence":0.99,"source":"t"}]`)
	_, al3 := get2(srv.URL+"/v1/alerts", "tok-admin")
	if !strings.Contains(al3, "intel_hit|redis.kbmon.cn|ma-1") {
		t.Errorf("情报事件应产 intel_hit: %s", al3)
	}
	if i := strings.Index(al3, "\"items\""); i == 0 || !strings.Contains(al3[i:i+200], "intel_hit|redis.kbmon.cn|ma-1") {
		t.Error("置信度 0.99 应排首位（FR-MON-004 按置信度排序）")
	}

	// 监控器列表含历史（FR-MON-001「可查询历史」）
	_, ms := get2(srv.URL+"/v1/monitors", "tok-admin")
	if !strings.Contains(ms, "15min") || !strings.Contains(ms, `"trigger":"manual"`) || !strings.Contains(ms, `"trigger":"import:vuln"`) {
		t.Errorf("历史留痕缺失: %s", ms)
	}
	if resp, _ = post(t, srv.URL, "/v1/monitors/99/run", "tok-admin", ``); resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知监控器应 404: %d", resp.StatusCode)
	}
}

func TestOwnershipQueueResolve(t *testing.T) {
	srv := newM1Server(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-r","name":"复核公司","short":"复核","root_domains":["kbrev.cn"]}`)
	post(t, srv.URL, "/v1/ownership:judge", "tok-admin", `{"tenant_id":"t-r","domain":"maybe.cn","signals":{"keyword_cooccur":3}}`)
	_, q := get2(srv.URL+"/v1/ownership/queue", "tok-admin")
	if !strings.Contains(q, "maybe.cn") {
		t.Fatalf("疑似应入队: %s", q)
	}
	// 缺 reviewer 必填 → 400
	resp, _ := post(t, srv.URL, "/v1/ownership/queue/1/resolve", "tok-admin", `{"verdict":"无关"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reviewer 必填: %d", resp.StatusCode)
	}
	resp, _ = post(t, srv.URL, "/v1/ownership/queue/1/resolve", "tok-admin", `{"verdict":"无关","reviewer":"alice"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("复核出口失败: %d", resp.StatusCode)
	}
	_, q2 := get2(srv.URL+"/v1/ownership/queue", "tok-admin")
	if strings.Contains(q2, "maybe.cn") {
		t.Error("resolve 后应出队（人工出口，不静默丢弃）")
	}
	if resp, _ = post(t, srv.URL, "/v1/ownership/queue/99/resolve", "tok-admin", `{"verdict":"无关","reviewer":"bob"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知 seq 应 404: %d", resp.StatusCode)
	}
}
